import asyncio
import base64
import binascii
import hashlib
import logging
import random
import re
import ssl
import socket
from typing import Optional, Callable
import xml.etree.ElementTree as ET

BUFF_SIZE = 512
_LOGGER = logging.getLogger("nicegate")

INITIAL_RECONNECT_DELAY = 15 
MAX_RECONNECT_DELAY = 300
BACKOFF_FACTOR = 2

class NiceGateApi:
    """API Standalone per Nice IT4WIFI."""

    def __init__(self, host: str, mac: str, pwd: str, on_status_callback: Callable[[str], None] = None):
        self.host = host
        self.target = mac
        self.source = "android"
        self.username = "homeassisstant"
        self.descr = ""
        self.pwd = pwd
        self.on_status_callback = on_status_callback 

        self.client_challenge = f"{random.randint(1, 9999999):08x}".upper()
        self.server_challenge = ""
        self.command_sequence = 1
        self.command_id = 0
        self.session_id = 1
        self.gate_status: Optional[str] = None

        self.serv_reader: Optional[asyncio.StreamReader] = None
        self.serv_writer: Optional[asyncio.StreamWriter] = None
        self.update_callback: Optional[Callable[[], asyncio.Future]] = None

        self._supervisor_task: Optional[asyncio.Task] = None
        self._shutdown_event = asyncio.Event()
        self._connection_lost = asyncio.Event()
        self._ready_event = asyncio.Event()
        self._reconnect_delay = INITIAL_RECONNECT_DELAY

    async def start(self):
        """Start the connection supervisor."""
        if self._supervisor_task is None or self._supervisor_task.done():
            _LOGGER.info("Starting NiceGate API supervisor...")
            self._shutdown_event.clear()
            self._supervisor_task = asyncio.create_task(self._connection_supervisor())

    async def close(self):
        """Stop the supervisor and close the connection."""
        if self._supervisor_task and not self._supervisor_task.done():
            _LOGGER.info("Closing NiceGate API supervisor...")
            self._shutdown_event.set()
            self._supervisor_task.cancel()
            try:
                await self._supervisor_task
            except asyncio.CancelledError:
                _LOGGER.warning("Supervisor task was cancelled.")
            _LOGGER.info("NiceGate API supervisor closed.")
        await self.disconnect()


    def __get_setup_code_check(self, setup_code: str) -> str:
        client_challenge = self.__hex_to_bytearray(self.client_challenge)
        setup_code_check = (
            bytes(setup_code, "utf-8")
            + client_challenge[::-1]
            + bytes("Nice4U", "utf-8")
        )
        crc32 = binascii.crc32(setup_code_check) & 0xFFFFFFFF
        return f"{crc32:08X}"
    
    async def pair(self, setup_code:str)->str:
        self.pwd = None
        writer = None
        if self.username is None or self.username == "":
            return None
        try:
            ctx = ssl.SSLContext(ssl.PROTOCOL_TLSv1)
            ctx.check_hostname = False
            ctx.verify_mode = ssl.CERT_NONE
            ctx.set_ciphers("ALL:@SECLEVEL=0")
            ctx.options |= 0x4
            await asyncio.sleep(0.01)
            reader, writer = await asyncio.open_connection(self.host, 443, ssl=ctx)

            msg = self.__build_message(
                'PAIR',
                (f'<Authentication username="{self.username}" cc="{self.client_challenge}" '
                 f'check="{self.__get_setup_code_check(setup_code)}" CType="phone" OSType="Android" '
                 'OSVer="6.0.1" desc="hass integration" />')
            )
            writer.write(msg)
            await writer.drain()
            pair = await self.__recvall()  # Removed reader argument
            match = re.search(r'<Authentication\s+id=[\'"]?([^\'" >]+)[\'"]?\s+username=[\'"]?([^\'" >]+)[\'"]?\s+pwd=[\'"]?([^\'" >]+)[\'"]?', pair)
            if match:
                self.pwd = match.groups()[2]
                _LOGGER.debug(f"User paired. Password {self.pwd}")
                return self.pwd
            else:
                _LOGGER.warning("No user found")
                return None
        except ConnectionError as error_msg:
            _LOGGER.error(error_msg, exc_info=True)
        except TimeoutError:
            _LOGGER.warning("Timeout")
        except Exception as ex:
            _LOGGER.error(ex, exc_info=True)

        if writer is not None:
            await writer.close()  # Ensure to await the close

        return self.pwd
    

    async def _connection_supervisor(self):
        _LOGGER.info("Connection supervisor started.")
        while not self._shutdown_event.is_set():
            try:
                if not await self._connect_and_handshake():
                    raise ConnectionError("Failed to connect and complete handshake.")

                _LOGGER.info("Connection successful.")
                self._reconnect_delay = INITIAL_RECONNECT_DELAY
                self._ready_event.set()
                
                await self.status()
                
                keep_alive_task = asyncio.create_task(self._keep_alive_loop())
                recv_loop_task = asyncio.create_task(self._recvloop())
                tasks = [keep_alive_task, recv_loop_task]

                done, pending = await asyncio.wait(tasks, return_when=asyncio.FIRST_COMPLETED)

                for task in pending:
                    task.cancel()
                await asyncio.gather(*pending, return_exceptions=True)

            except asyncio.CancelledError:
                _LOGGER.info("Connection supervisor cancelled.")
                break
            except Exception as e:
                _LOGGER.error(f"Supervisor error: {e}")
            
            await self.disconnect()
            _LOGGER.info(f"Waiting {self._reconnect_delay}s before reconnecting...")
            await asyncio.sleep(self._reconnect_delay)
            self._reconnect_delay = min(self._reconnect_delay * BACKOFF_FACTOR, MAX_RECONNECT_DELAY)

    def set_update_callback(self, callback: Callable[[], asyncio.Future]):
        self.update_callback = callback

    async def get_status(self) -> Optional[str]:
        if self.gate_status is None:
            await self.status()
        return self.gate_status

    # ===========================
    # Protocol primitives
    # ===========================

    def __hex_to_bytearray(self, hex_str: str) -> bytes:
        return bytes.fromhex(hex_str)

    def __sha256(self, *args: bytes) -> bytes:
        hsh = hashlib.sha256()
        for arg in args:
            hsh.update(arg)
        return hsh.digest()

    def __invert_array(self, data: bytes) -> bytes:
        return data[::-1]

    def __generate_command_id(self, session_id) -> int:
        i = self.command_sequence
        self.command_sequence = i + 1
        return (i << 8) | (int(session_id) & 255)

    def __build_signature(self, xml_command: str) -> str:
        client_challenge = self.__hex_to_bytearray(self.client_challenge)
        server_challenge = self.__hex_to_bytearray(self.server_challenge)

        pairing_password = base64.b64decode(self.pwd)
        session_password = self.__sha256(
            pairing_password,
            self.__invert_array(server_challenge),
            self.__invert_array(client_challenge),
        )

        msg_hash = self.__sha256(xml_command.encode())
        sign = self.__sha256(msg_hash, session_password)
        return "<Sign>" + base64.b64encode(sign).decode("utf-8") + "</Sign>"

    def __build_message(self, command_type: str, body: str) -> bytes:
        self.command_id = self.__generate_command_id(self.session_id)
        start_request = (
        '<Request id="{}" source="{}" target="{}" gw="gwID" protocolType="NHK" '
        'protocolVersion="1.0" type="{}">\r\n'.format(
        self.command_id, self.source, self.target, command_type
        )
        )
        end_request = "</Request>\r\n"
        signed = self.__build_signature(start_request + body) if self.__is_sign_needed(command_type) else ""
        msg = self.__wrap_message(start_request + body + signed + end_request)
        return msg

    def __is_sign_needed(self, command_type: str) -> bool:
        return command_type not in ("CONFIG", "VERIFY", "CONNECT", "PAIR")

    def __wrap_message(self, xml: str) -> bytes:
        return ("\u0002" + xml + "\u0003").encode()
    
    # ===========================
    # Connection / handshake
    # ===========================

    async def _ensure_connected(self) -> bool:
        try:
            await asyncio.wait_for(self._ready_event.wait(), timeout=15)
            return True
        except asyncio.TimeoutError:
            _LOGGER.warning("Timeout waiting for connection readiness.")
            return False

    async def _connect_and_handshake(self) -> bool:
        try:
            ctx = ssl.SSLContext(ssl.PROTOCOL_TLSv1)
            ctx.check_hostname = False
            ctx.verify_mode = ssl.CERT_NONE
            ctx.set_ciphers("ALL:@SECLEVEL=0")
            ctx.options |= 0x4

            _LOGGER.debug("Opening connection to %s:443", self.host)
            reader, writer = await asyncio.open_connection(self.host, 443, ssl=ctx)
            
            sock = writer.get_extra_info('socket')
            if sock:
                try:
                    sock.setsockopt(socket.SOL_SOCKET, socket.SO_KEEPALIVE, 1)
                    if hasattr(socket, 'TCP_KEEPIDLE'):
                        sock.setsockopt(socket.IPPROTO_TCP, socket.TCP_KEEPIDLE, 60)
                    if hasattr(socket, 'TCP_KEEPINTVL'):
                        sock.setsockopt(socket.IPPROTO_TCP, socket.TCP_KEEPINTVL, 10)
                    if hasattr(socket, 'TCP_KEEPCNT'):
                        sock.setsockopt(socket.IPPROTO_TCP, socket.TCP_KEEPCNT, 3)
                except Exception as ex:
                    _LOGGER.warning(f"Could not set socket keepalive options: {ex}")

            self.serv_reader = reader
            self.serv_writer = writer

            # VERIFY
            verify_msg = self.__build_message("VERIFY", f'<User username="{self.username}"/>')
            self.serv_writer.write(verify_msg)
            await self.serv_writer.drain()
            verify = await self.__recvall()
            if not re.search(r'Authentication\sid=[\'\"]?([^\'\" >]+)', verify):
                raise ConnectionError("Missing Authentication ID in VERIFY response")
            self.__find_session_id(verify)

            # CONNECT
            connect_msg = self.__build_message("CONNECT", f'<Authentication username="{self.username}" cc="{self.client_challenge}"/>')
            self.serv_writer.write(connect_msg)
            await self.serv_writer.drain()
            connect = await self.__recvall()
            
            match = re.search(r'sc=[\'\"]?([^\'\" >]+)', connect)
            if not match:
                raise ConnectionError("Server challenge not found in CONNECT response")
            self.server_challenge = match.group(1)
            
            _LOGGER.info("Connection and handshake successful.")
            return True

        except Exception as e:
            _LOGGER.error("connect_and_handshake failed: %s", e)
            await self.disconnect()
            return False

    async def disconnect(self) -> None:
        _LOGGER.debug("Disconnecting and resetting state...")
        if self.serv_writer:
            try:
                self.serv_writer.close()
                await self.serv_writer.wait_closed()
                _LOGGER.info("Connection closed successfully.")
            except Exception as e:
                _LOGGER.error(f"Error closing connection: {e}")

        self.serv_reader = None
        self.serv_writer = None
        self.server_challenge = ""
        self.session_id = 1
        self.command_sequence = 1
        self.gate_status = None
        self._ready_event.clear()

    # ===========================
    # XML Parsing Fix
    # ===========================

    async def __process_event(self, msg: str) -> None:
        try:
            clean_xml = re.sub(r'\sxmlns="[^"]+"', '', msg, count=1)
            resp = ET.fromstring(clean_xml)
        except Exception as e:
            _LOGGER.exception("Failed to parse incoming XML: %s error: %s", msg, e)
            return

        if resp.tag in ("Event", "Response"):
            node = resp.find(".//DoorStatus")
            
            if node is None:
                _LOGGER.debug("Node DoorStatus not found in XML tree.")
            
            new_status = node.text.strip() if node is not None else None
            
            if new_status and new_status != self.gate_status:
                self.gate_status = new_status
                _LOGGER.info("Gate status changed to: '%s'", self.gate_status)
                
                if self.on_status_callback:
                    try:
                        self.on_status_callback(self.gate_status)
                    except Exception as e:
                        _LOGGER.error(f"Error in status callback: {e}")

    async def _send_command(self, command_type: str, body: str = ""):
        if not await self._ensure_connected():
            _LOGGER.error("Cannot send command '%s': not connected/ready.", command_type)
            return
        
        if not self.serv_writer:
            _LOGGER.error("Cannot send command '%s': writer is not available.", command_type)
            return

        try:
            msg = self.__build_message(command_type, body)
            self.serv_writer.write(msg)
            await self.serv_writer.drain()
            _LOGGER.debug("Sent command: %s", command_type)
        except Exception as e:
            _LOGGER.exception("Failed to send command '%s': %s", command_type, e)
            raise e

    async def status(self) -> None:
        _LOGGER.debug("Requesting status...")
        await self._send_command("STATUS")

    async def info(self) -> None:
        _LOGGER.debug("Requesting info...")
        await self._send_command("INFO")

    async def change(self, command: str) -> None:
        body = f'<Devices><Device id="1"><Services><DoorAction>{command}</DoorAction></Services></Device></Devices>'
        _LOGGER.debug("Sending change command: %s", command)
        await self._send_command("CHANGE", body)

    async def t4(self, command: str) -> None:
        body = f'<Devices><Device id="1"><Services><T4Action>{command}</T4Action></Services></Device></Devices>'
        _LOGGER.debug("Sending T4 command: %s", command)
        await self._send_command("CHANGE", body)

    async def check(self) -> None:
        body = f'<Authentication id="{self.session_id}" username="{self.username}"/>'
        _LOGGER.debug("Sending check command...")
        await self._send_command("CHECK", body)

    async def _recvloop(self) -> None:
        _LOGGER.debug("Receive loop started.")
        try:
            while not self._shutdown_event.is_set():
                msg = await self.__recvall()
                await self.__process_event(msg)
        except (asyncio.CancelledError, ConnectionError):
            _LOGGER.debug("Receive loop stopping.")
        except Exception as e:
            _LOGGER.exception("Unhandled exception in recvloop: %s", e)
        finally:
            _LOGGER.info("Receive loop terminated.")

    async def __recvall(self) -> str:
        if not self.serv_reader:
            raise ConnectionError("StreamReader is not available.")
        
        try:
            part = await asyncio.wait_for(self.serv_reader.readuntil(b"\x03"), timeout=150)
            if not part:
                raise ConnectionError("Socket closed by peer.")

            stx_pos = part.find(b"\x02")
            if stx_pos != -1:
                part = part[stx_pos + 1:]
            
            etx_pos = part.rfind(b"\x03")
            if etx_pos != -1:
                part = part[:etx_pos]

            answer = part.decode('utf-8')
            self.__find_session_id(answer)
            return answer
            
        except asyncio.IncompleteReadError:
            raise ConnectionError("Socket closed prematurely.")
        except asyncio.TimeoutError:
            _LOGGER.debug("Read timeout in __recvall, connection likely idle.")
            raise ConnectionError("Read timed out.")
        except OSError as e:
            raise ConnectionError(f"Socket error during read: {e}")

    async def _keep_alive_loop(self) -> None:
        _LOGGER.debug("Keep-alive loop started.")
        try:
            while not self._shutdown_event.is_set():
                await asyncio.sleep(60)
                await self.check()
        except asyncio.CancelledError:
            _LOGGER.info("Keep-alive loop cancelled.")
        except Exception as e:
            _LOGGER.warning("Keep-alive check failed: %s", e)
        finally:
            _LOGGER.info("Keep-alive loop terminated.")

    def __find_session_id(self, msg: str) -> None:
        match = re.search(r'Authentication\sid=[\'\"]?([^\'\" >]+)', msg)
        if match:
            self.session_id = match.group(1)
            _LOGGER.debug("Session ID found: %s", self.session_id)

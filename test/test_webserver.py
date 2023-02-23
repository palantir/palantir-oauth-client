import pytest
import socket
from expects import *
from mockito import ANY, mock, patch, verify, verifyZeroInteractions, when

from palantir_oauth_client._flow import Flow
from palantir_oauth_client._webserver import find_open_port, run_local_server
from palantir_oauth_client.errors import ConnectionError


class TestWebserver:

    socket_instance: socket.socket

    @pytest.fixture(autouse=True)
    def before(self):
        self.socket_instance = mock(socket.socket)

        when(self.socket_instance).bind(ANY)
        when(self.socket_instance).close()

    def test_find_open_port_finds_start_port(self):
        when(self.socket_instance).listen(1)

        def mock_socket(family, type_):
            return self.socket_instance

        with patch(socket, "socket", mock_socket):
            port = find_open_port(9999)
            expect(port).to(equal(9999))

    def test_find_open_port_finds_stop_port(self):
        when(self.socket_instance).listen(1).thenRaise(
            *([socket.error()] * 99)
        ).thenAnswer(lambda _: None)

        def mock_socket(family, type_):
            return self.socket_instance

        with patch(socket, "socket", mock_socket):
            port = find_open_port(9000, stop=9100)
            expect(port).to(equal(9099))

    def test_find_open_port_returns_none(self):
        when(self.socket_instance).listen(1).thenRaise(socket.error())

        def mock_socket(family, type_):
            return self.socket_instance

        with patch(socket, "socket", mock_socket):
            port = find_open_port(9999)
            expect(port).to(be_none)
        verify(self.socket_instance, times=100).listen(1)

    def test_run_local_server_calls_flow(self):
        flow = mock(Flow)
        when(flow).run_local_server(host="127.0.0.1", port=ANY)

        run_local_server(flow)
        verify(flow).run_local_server(host="127.0.0.1", port=ANY)

    def test_run_local_server_raises_connection_error(self):
        flow = mock(Flow)
        when(self.socket_instance).listen(1).thenRaise(socket.error())

        def mock_socket(family, type_):
            return self.socket_instance

        with patch(socket, "socket", mock_socket):
            expect(lambda: run_local_server(flow)).to(
                raise_error(ConnectionError)
            )
        verifyZeroInteractions(flow)

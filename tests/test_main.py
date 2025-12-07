"""Tests for main entry point and module initialization."""

from unittest.mock import patch

import pytest

from mcp_coroot import server
from mcp_coroot.server import StaticOAuthProvider, StaticTokenVerifier


class TestStaticTokenVerifier:
    """Test the StaticTokenVerifier class."""

    @pytest.mark.asyncio
    async def test_verify_valid_token(self):
        """Test that a valid token returns an AccessToken."""
        verifier = StaticTokenVerifier("secret123")
        result = await verifier.verify_token("secret123")

        assert result is not None
        assert result.token == "secret123"
        assert result.client_id == "mcp-client"
        assert result.scopes == []

    @pytest.mark.asyncio
    async def test_verify_invalid_token(self):
        """Test that an invalid token returns None."""
        verifier = StaticTokenVerifier("secret123")
        result = await verifier.verify_token("wrong-token")

        assert result is None

    @pytest.mark.asyncio
    async def test_verify_empty_token(self):
        """Test that an empty token returns None."""
        verifier = StaticTokenVerifier("secret123")
        result = await verifier.verify_token("")

        assert result is None


class TestMainFunction:
    """Test the main function and entry point."""

    @pytest.fixture(autouse=True)
    def reset_mcp_auth(self):
        """Ensure mcp.auth is reset between tests to avoid leakage."""
        server.mcp.auth = None
        yield
        server.mcp.auth = None

    def test_main_function_exists(self):
        """Test that main function exists."""
        assert hasattr(server, "main")
        assert callable(server.main)

    @patch("mcp_coroot.server.mcp.run")
    @patch("sys.argv", ["mcp-coroot"])
    def test_main_calls_mcp_run_stdio_default(self, mock_run):
        """Test that main() calls mcp.run() with stdio by default."""
        server.main()
        mock_run.assert_called_once_with()

    @patch("mcp_coroot.server.mcp.run")
    @patch("sys.argv", ["mcp-coroot", "--transport", "sse"])
    def test_main_calls_mcp_run_with_sse(self, mock_run):
        """Test that main() calls mcp.run() with SSE transport."""
        server.main()
        mock_run.assert_called_once_with(
            transport="sse",
            host="127.0.0.1",
            port=8000,
        )
        assert server.mcp.auth is None

    @patch("mcp_coroot.server.mcp.run")
    @patch(
        "sys.argv", ["mcp-coroot", "--transport", "streamable-http", "--port", "9000"]
    )
    def test_main_calls_mcp_run_with_streamable_http(self, mock_run):
        """Test that main() calls mcp.run() with streamable-http transport."""
        server.main()
        mock_run.assert_called_once_with(
            transport="streamable-http",
            host="127.0.0.1",
            port=9000,
        )
        assert server.mcp.auth is None

    @patch("mcp_coroot.server.mcp.run")
    @patch("sys.argv", ["mcp-coroot", "--transport", "sse", "--host", "0.0.0.0"])
    def test_main_custom_host(self, mock_run):
        """Test that main() accepts custom host."""
        server.main()
        mock_run.assert_called_once_with(
            transport="sse",
            host="0.0.0.0",
            port=8000,
        )
        assert server.mcp.auth is None

    @patch("mcp_coroot.server.mcp.run")
    @patch("sys.argv", ["mcp-coroot", "--transport", "sse", "--auth-token", "mysecret"])
    def test_main_with_auth_token_cli(self, mock_run):
        """Test that main() creates auth verifier from CLI argument."""
        server.main()

        # Auth token should be attached to the mcp instance, not passed to run()
        assert isinstance(server.mcp.auth, StaticOAuthProvider)
        call_args = mock_run.call_args
        assert "auth" not in call_args.kwargs

    @patch("mcp_coroot.server.mcp.run")
    @patch.dict("os.environ", {"MCP_AUTH_TOKEN": "envsecret"})
    @patch("sys.argv", ["mcp-coroot", "--transport", "sse"])
    def test_main_with_auth_token_env(self, mock_run):
        """Test that main() creates auth verifier from environment variable."""
        server.main()

        # Auth token should be attached to the mcp instance, not passed to run()
        assert isinstance(server.mcp.auth, StaticOAuthProvider)
        call_args = mock_run.call_args
        assert "auth" not in call_args.kwargs

    @patch("mcp_coroot.server.mcp.run")
    @patch("sys.argv", ["mcp-coroot", "--auth-token", "mysecret"])
    def test_main_stdio_ignores_auth_token(self, mock_run):
        """Test that auth token is ignored for stdio transport."""
        server.main()
        # For stdio, mcp.run() is called without arguments
        mock_run.assert_called_once_with()
        # Stdio should not set auth even if token provided
        assert server.mcp.auth is None

    def test_server_initialization(self):
        """Test that the MCP server is initialized correctly."""
        # Import the server module
        import mcp_coroot.server  # noqa: F401

        # Verify the mcp object exists and has correct name
        assert hasattr(server, "mcp")
        # The mcp object should have been created with the name "mcp-coroot"
        # We can't easily test FastMCP internals without mocking at import time


class TestGetClient:
    """Test get_client function."""

    def test_get_client_singleton(self):
        """Test that get_client returns the same instance."""
        # Reset the global client
        server._client = None

        with patch("mcp_coroot.server.CorootClient") as mock_client_class:
            mock_instance = mock_client_class.return_value

            # First call creates client
            client1 = server.get_client()
            assert client1 == mock_instance
            mock_client_class.assert_called_once()

            # Second call returns same instance
            client2 = server.get_client()
            assert client2 == client1
            # Still only called once
            mock_client_class.assert_called_once()

    def test_get_client_error_handling(self):
        """Test get_client error handling."""
        # Reset the global client
        server._client = None

        with patch("mcp_coroot.server.CorootClient") as mock_client_class:
            mock_client_class.side_effect = ValueError("Invalid config")

            with pytest.raises(ValueError) as exc_info:
                server.get_client()

            assert "Coroot credentials not configured" in str(exc_info.value)

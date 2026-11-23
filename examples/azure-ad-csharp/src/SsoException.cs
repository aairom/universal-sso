namespace UniversalSso.Client;

/// <summary>Base class for every error raised by this client.</summary>
public class SsoException : Exception
{
    /// <summary>Creates an error with a message.</summary>
    public SsoException(string message) : base(message) { }

    /// <summary>Creates an error with a message and a cause.</summary>
    public SsoException(string message, Exception inner) : base(message, inner) { }
}

/// <summary>A configuration value is missing or invalid.</summary>
public sealed class ConfigException(string message) : SsoException(message);

/// <summary>The gateway or network could not be reached, or the reply was unusable.</summary>
public sealed class TransportException : SsoException
{
    /// <summary>Creates a transport error.</summary>
    public TransportException(string message) : base(message) { }

    /// <summary>Creates a transport error with a cause.</summary>
    public TransportException(string message, Exception inner) : base(message, inner) { }
}

/// <summary>The login redirect failed the client-side safety policy.</summary>
public sealed class PolicyException(string message) : SsoException(message);

/// <summary>The flow needs a browser because a redirect leaves the gateway host.</summary>
public sealed class LeavesGatewayException()
    : SsoException("redirect leaves the gateway host: open the URL in a browser");

/// <summary>The gateway answered with its structured error body <c>{"code","message"}</c>.</summary>
public sealed class ApiException : SsoException
{
    /// <summary>Creates an API error.</summary>
    public ApiException(int status, string code, string message)
        : base($"gateway error {status} [{code}]: {message}")
    {
        Status = status;
        Code = code;
    }

    /// <summary>HTTP status code.</summary>
    public int Status { get; }

    /// <summary>Machine-readable code such as <c>PROVIDER_NOT_FOUND</c>.</summary>
    public string Code { get; }
}

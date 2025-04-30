namespace sharp_aws_creds;

public class AuthRequest
{
    public string Username { get; set; }
    public string Password { get; set; }
    public AuthOptions Options { get; set; }
}
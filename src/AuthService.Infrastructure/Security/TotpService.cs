using AuthService.Application.Common.Interfaces;
using OtpNet;

namespace AuthService.Infrastructure.Security;

public sealed class TotpService : ITotpService
{
    private const int StepSeconds = 30;
    private const int VerificationWindow = 1; // ±1 step = ±30 s tolerance

    public string GenerateSecret()
    {
        var key = KeyGeneration.GenerateRandomKey(20); // 160-bit key
        return Base32Encoding.ToString(key);
    }

    public string GenerateQrCodeUri(string issuer, string email, string base32Secret)
    {
        var encodedIssuer = Uri.EscapeDataString(issuer);
        var encodedEmail  = Uri.EscapeDataString(email);
        var label         = $"{encodedIssuer}:{encodedEmail}";
        return $"otpauth://totp/{label}?secret={base32Secret}&issuer={encodedIssuer}&algorithm=SHA1&digits=6&period={StepSeconds}";
    }

    public bool VerifyCode(string base32Secret, string code)
    {
        if (string.IsNullOrWhiteSpace(code) || code.Length != 6 || !code.All(char.IsDigit))
            return false;

        try
        {
            var key  = Base32Encoding.ToBytes(base32Secret);
            var totp = new Totp(key, step: StepSeconds);
            return totp.VerifyTotp(code, out _, new VerificationWindow(VerificationWindow, VerificationWindow));
        }
        catch
        {
            return false;
        }
    }
}

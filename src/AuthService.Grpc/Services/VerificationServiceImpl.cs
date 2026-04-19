using AuthService.Application.Common.Messaging;
using AuthService.Application.Features.Verification.Commands;
using AuthService.Grpc.Helpers;
using AuthService.Grpc.Protos;
using Grpc.Core;

namespace AuthService.Grpc.Services;

public sealed class VerificationServiceImpl(
    ICommandHandler<VerifyEmailCommand,          VerifyEmailResult>          verifyEmail,
    ICommandHandler<RequestPasswordResetCommand, RequestPasswordResetResult> requestPasswordReset,
    ICommandHandler<ResetPasswordCommand,        ResetPasswordResult>        resetPassword)
    : VerificationService.VerificationServiceBase
{
    public override async Task<VerifyEmailResponse> VerifyEmail(
        VerifyEmailRequest request, ServerCallContext context)
    {
        var result = await verifyEmail.HandleAsync(
            new VerifyEmailCommand(
                TenantId: GrpcTenantHelper.GetRequiredTenantId(context),
                Token:    request.Token,
                PeerIp:   PeerIp(context)),
            context.CancellationToken);

        return new VerifyEmailResponse { Success = result.Success };
    }

    public override async Task<RequestPasswordResetResponse> RequestPasswordReset(
        RequestPasswordResetRequest request, ServerCallContext context)
    {
        var result = await requestPasswordReset.HandleAsync(
            new RequestPasswordResetCommand(
                TenantId: GrpcTenantHelper.GetRequiredTenantId(context),
                Email:    string.IsNullOrWhiteSpace(request.Email) ? null : request.Email),
            context.CancellationToken);

        return new RequestPasswordResetResponse { Success = result.Success };
    }

    public override async Task<ResetPasswordResponse> ResetPassword(
        ResetPasswordRequest request, ServerCallContext context)
    {
        var result = await resetPassword.HandleAsync(
            new ResetPasswordCommand(
                TenantId:    GrpcTenantHelper.GetRequiredTenantId(context),
                Token:       request.Token,
                NewPassword: request.NewPassword,
                PeerIp:      PeerIp(context)),
            context.CancellationToken);

        return new ResetPasswordResponse { Success = result.Success };
    }

    private static string PeerIp(ServerCallContext context)
    {
        var peer = context.Peer ?? "unknown";
        var colon = peer.LastIndexOf(':');
        return colon > 0 ? peer[..colon] : peer;
    }
}

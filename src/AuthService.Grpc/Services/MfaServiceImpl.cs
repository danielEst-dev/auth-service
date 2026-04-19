using AuthService.Application.Common.Messaging;
using AuthService.Application.Features.Mfa.Commands;
using AuthService.Grpc.Helpers;
using AuthService.Grpc.Protos;
using Grpc.Core;

namespace AuthService.Grpc.Services;

public sealed class MfaServiceImpl(
    ICommandHandler<EnableMfaCommand,             EnableMfaResult>             enableMfa,
    ICommandHandler<VerifyMfaCommand,             VerifyMfaResult>             verifyMfa,
    ICommandHandler<DisableMfaCommand,            DisableMfaResult>            disableMfa,
    ICommandHandler<GenerateRecoveryCodesCommand, GenerateRecoveryCodesResult> generateRecoveryCodes)
    : MfaService.MfaServiceBase
{
    public override async Task<EnableMfaResponse> EnableMfa(EnableMfaRequest request, ServerCallContext context)
    {
        var result = await enableMfa.HandleAsync(
            new EnableMfaCommand(
                TenantId: GrpcTenantHelper.GetRequiredTenantId(context),
                UserId:   ParseUserId(request.UserId)),
            context.CancellationToken);

        return new EnableMfaResponse { Secret = result.Secret, QrCodeUri = result.QrCodeUri };
    }

    public override async Task<VerifyMfaResponse> VerifyMfa(VerifyMfaRequest request, ServerCallContext context)
    {
        var result = await verifyMfa.HandleAsync(
            new VerifyMfaCommand(
                TenantId: GrpcTenantHelper.GetRequiredTenantId(context),
                UserId:   ParseUserId(request.UserId),
                Code:     request.Code),
            context.CancellationToken);

        return new VerifyMfaResponse { Success = result.Success, IsConfirmed = result.IsConfirmed };
    }

    public override async Task<DisableMfaResponse> DisableMfa(DisableMfaRequest request, ServerCallContext context)
    {
        var result = await disableMfa.HandleAsync(
            new DisableMfaCommand(
                TenantId: GrpcTenantHelper.GetRequiredTenantId(context),
                UserId:   ParseUserId(request.UserId),
                Code:     request.Code),
            context.CancellationToken);

        return new DisableMfaResponse { Success = result.Success };
    }

    public override async Task<GenerateRecoveryCodesResponse> GenerateRecoveryCodes(
        GenerateRecoveryCodesRequest request, ServerCallContext context)
    {
        var result = await generateRecoveryCodes.HandleAsync(
            new GenerateRecoveryCodesCommand(
                TenantId: GrpcTenantHelper.GetRequiredTenantId(context),
                UserId:   ParseUserId(request.UserId)),
            context.CancellationToken);

        var response = new GenerateRecoveryCodesResponse();
        response.Codes.AddRange(result.Codes);
        return response;
    }

    private static Guid ParseUserId(string userId)
    {
        if (!Guid.TryParse(userId, out var id))
            throw new RpcException(new Status(StatusCode.InvalidArgument, "Invalid user ID."));
        return id;
    }
}

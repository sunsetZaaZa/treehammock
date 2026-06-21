using System.ComponentModel.DataAnnotations;
using System.Diagnostics.CodeAnalysis;

using treehammock.RiggingSupport.Status;

namespace treehammock.Models.Activation;

public class ActivationUnSubscribeRequest
{
    public const int MaxEmailAddressLength = 1024;

    [SetsRequiredMembers]
    public ActivationUnSubscribeRequest(string emailAddress) =>
        this.emailAddress = emailAddress;

    [Required(AllowEmptyStrings = false)]
    [EmailAddress]
    [StringLength(MaxEmailAddressLength)]
    public required string emailAddress { get; set; }
}

public class ActivationUnSubscribeResponse
{
    [SetsRequiredMembers]
    public ActivationUnSubscribeResponse(Pass result) =>
        this.result = result;

    public required Pass result { get; set; }
}

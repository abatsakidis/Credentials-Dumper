namespace Credentials_Dump
{
    public enum CredentialType : uint
    {
        None = 0,
        Generic = 1,
        DomainPassword = 2,
        DomainCertificate = 3,
        DomainVisiblePassword = 4,
        GenericCertificate = 5,
        DomainExtended = 6,
        Maximum = 7,
        CredTypeMaximum = Maximum + 1000
    }
}

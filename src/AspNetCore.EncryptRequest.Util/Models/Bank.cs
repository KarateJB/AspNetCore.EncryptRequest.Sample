using System.Collections.Generic;

namespace AspNetCore.EncryptRequest.Util.Models
{
    public class Bank
    {
        public string? Name { get; set; }
        public IList<Merchant>? Merchants { get; set; }

    }

    public class Merchant
    {
        public string? Name { get; set; }
        public string? Address { get; set; }
    }
}
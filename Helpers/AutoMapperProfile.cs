using AutoMapper;
using Server.Entities;
using Server.Models.Accounts;

namespace Server.Helpers
{
    public class AutoMapperProfile : Profile
    {
        /// <summary>
        /// The auto mapper profile contains the mapping configuration used by the application
        /// It enables automatic mapping of property values between different class types based on property names
        /// </summary>
        public AutoMapperProfile()
        {
            CreateMap<Account, AccountResponse>();

            CreateMap<Account, AuthenticateResponse>();

            CreateMap<RegisterRequest, Account>();

            CreateMap<CreateRequest, Account>();


            // The mapping from UpdateRequest to Account includes some custom configuration to ignore empty properties
            // on the request model when mapping to an account entity, this is to make fields optional when updating an account.
            CreateMap<UpdateRequest, Account>()
                .ForAllMembers(x => x.Condition(
                    (src, dest, prop) =>
                    {
                        // ignore null & empty string properties
                        if (prop == null) return false;
                        if (prop.GetType() == typeof(string) && string.IsNullOrEmpty((string)prop)) return false;

                        // ignore null role
                        if (x.DestinationMember.Name == "Role" && src.Role == null) return false;

                        return true;
                    }
                ));
        }
    }
}
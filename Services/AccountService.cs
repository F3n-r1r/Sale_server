using System;
using System.Security.Cryptography;
using System.Threading.Tasks;
using MongoDB.Driver;
using Server.Models;
using Server.Settings;

namespace Server.Services
{
    public class AccountService
    {
        private readonly IMongoCollection<Account> _accounts;
        private readonly IEmailService _emailService;

        public AccountService(DatabaseSettings settings, IEmailService emailService)
        {
            var client = new MongoClient(settings.ConnectionString);
            var database = client.GetDatabase(settings.DatabaseName);
            _accounts = database.GetCollection<Account>(settings.AccountsCollectionName);

            _emailService = emailService;
        }


        /// <summary>
        /// Method to check if an account exists
        /// </summary>
        public async Task<bool> Exists(Account account)
        {
            if (await _accounts.Find(x => x.Email == account.Email).FirstOrDefaultAsync() != null)
            {
                return true;
            }
            return false;
        }


        /// <summary>
        /// 
        /// </summary>
        public async Task<Account> Create(Account account, string origin)
        {
            account.Created = DateTime.Now;
            account.Role = Role.User;
            account.Password = BCrypt.Net.BCrypt.HashPassword(account.Password);
            account.TermsAccepted = true;

            using var rngCryptoServiceProvider = new RNGCryptoServiceProvider();
            var randomBytes = new byte[40];
            rngCryptoServiceProvider.GetBytes(randomBytes);
            account.VerificationToken = BitConverter.ToString(randomBytes).Replace("-", ""); 

            await _accounts.InsertOneAsync(account);

            string verifyUrl = $"{origin}/account/verify?token={account.VerificationToken}";
            string message = $@"
                                <h1>Hello!</h1>
                                <p>Please click the link below to verify your newly created account</p>
                                <a href=""{verifyUrl}"">Verify Me</a>
                             ";

            await _emailService.Send(account.Email, "Sale account verification", message);

            return account;
        }


    }
}

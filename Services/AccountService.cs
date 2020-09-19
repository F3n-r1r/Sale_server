using System;
using System.Security.Cryptography;
using System.Threading.Tasks;
using Microsoft.AspNetCore.Http;
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
        /// Method to create a new account and send verification email to that account using the email service
        /// </summary>
        public async Task<bool> Verify(string Token)
        {
            Account account = await _accounts.Find(x => x.VerificationToken == Token).FirstOrDefaultAsync();
            
            if(account == null)
            {
                return false;
            }

            account.Verified = DateTime.Now;
            account.VerificationToken = null;

            var filter = Builders<Account>.Filter.Eq("Email", account.Email);
            var update = Builders<Account>.Update.Set(x => x.Verified, DateTime.Now).Set(x => x.VerificationToken, null);
            await _accounts.FindOneAndUpdateAsync(filter, update);

            return true;
        }



        /// <summary>
        /// Method to create a new account and send verification email to that account using the email service
        /// </summary>
        public async Task<Account> Create(Account account, HostString host)
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

            string verifyUrl = $"{host}/account/verify?token={account.VerificationToken}";
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

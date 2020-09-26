using System;
using System.IdentityModel.Tokens.Jwt;
using System.Security.Claims;
using System.Security.Cryptography;
using System.Text;
using System.Threading.Tasks;
using Microsoft.AspNetCore.Http;
using Microsoft.Extensions.Options;
using Microsoft.IdentityModel.Tokens;
using AutoMapper;
using MongoDB.Driver;
using Server.Models;
using Server.Settings;
using Server.Entities;
using Server.Models.Accounts;
using Server.Helpers;
using Microsoft.AspNetCore.Mvc.Infrastructure;
using BC = BCrypt.Net.BCrypt;
using System.Collections.Generic;

namespace Server.Services
{
    public class AccountService
    {
        private readonly IMongoCollection<Account> _accounts;
        private readonly IEmailService _emailService;
        private readonly IMapper _mapper;
        private readonly AuthSettings _authSettings;


        public AccountService(DatabaseSettings databaseSettings, IOptions<AuthSettings> authSettings, IEmailService emailService, IMapper mapper)
        {
            var client = new MongoClient(databaseSettings.ConnectionString);
            var database = client.GetDatabase(databaseSettings.DatabaseName);
            _accounts = database.GetCollection<Account>(databaseSettings.AccountsCollectionName);

            _authSettings = authSettings.Value;
            _mapper = mapper;
            _emailService = emailService;
        }





        /// <summary>
        /// Method to check if an account exists
        /// </summary>
        public async Task<bool> Exists(string email)
        {
            if (await _accounts.Find(x => x.Email == email).FirstOrDefaultAsync() != null)
            {
                return true;
            }
            return false;
        }





        /// <summary>
        /// Method to verify the email of a newly created account
        /// </summary>
        public async Task VerifyEmail(string Token)
        {
            Account account = await _accounts.Find(x => x.VerificationToken == Token).FirstOrDefaultAsync();  
            if(account == null)
            {
                throw new Exception();
            }

            var filter = Builders<Account>.Filter.Eq("Email", account.Email);
            var update = Builders<Account>.Update.Set(x => x.Verified, DateTime.Now).Set(x => x.VerificationToken, null);
            await _accounts.FindOneAndUpdateAsync(filter, update);
        }





        /// <summary>
        /// Method to send a email to the given account with a link to reset their password
        /// </summary>
        public async Task ForgotPassword(ForgotPasswordRequest model, string origin)
        {
            var account = await _accounts.Find(x => x.Email == model.Email).FirstOrDefaultAsync();
            if (account == null)
            {
                throw new Exception();
            }

            var resetToken = randomTokenString();
            var resetTokenExpires = DateTime.Now.AddDays(24);

            var filter = Builders<Account>.Filter.Eq("Email", account.Email);
            var update = Builders<Account>.Update.Set(x => x.ResetToken, resetToken).Set(x => x.ResetTokenExpires, resetTokenExpires);
            await _accounts.FindOneAndUpdateAsync(filter, update);

            string resetUrl = $"{origin}/api/v1/account/reset-password?token={resetToken}";
            string message = $@"
                                <p>Please click the below link to reset your password, the link will be valid for 1 day:</p>
                                <p><a href=""{resetUrl}"">{resetUrl}</a></p>
                            ";

            await _emailService.Send(account.Email, "Sale - Reset password", message);
        }





        /// <summary>
        /// Method to create a new account and send verification email to that account using the email service
        /// </summary>
        public async Task Register(RegisterRequest model, string origin)
        {
            var account = _mapper.Map<Account>(model);
            account.Role = Role.User;
            account.Created = DateTime.UtcNow;
            account.RefreshTokens = new List<RefreshToken>();
            account.VerificationToken = randomTokenString();
            account.Password = BC.HashPassword(model.Password);

            await _accounts.InsertOneAsync(account);

            string verifyUrl = $"{origin}/api/v1//account/verify?token={account.VerificationToken}";
            string message = $@"
                                <h1>Hello!</h1>
                                <p>Please click the link below to verify your newly created account</p>
                                <a href=""{verifyUrl}"">{verifyUrl}</a>
                             ";

            await _emailService.Send(account.Email, "Sale - Email verification", message);
        }





        /// <summary>
        /// Method to authenticate an account
        /// </summary>
        public async Task<AuthenticateResponse> Authenticate(AuthenticateRequest model, string ipAddress)
        {
            var account = await _accounts.Find(x => x.Email == model.Email).FirstOrDefaultAsync();
            if (account == null || !account.IsVerified || !BC.Verify(model.Password, account.Password))
            {
                throw new Exception();
            }

            var jwtToken = generateJwtToken(account);
            var refreshToken = generateRefreshToken(ipAddress);

            var filter = Builders<Account>.Filter.Eq("Email", account.Email);
            var update = Builders<Account>.Update.Push("RefreshTokens", refreshToken);            

            await _accounts.FindOneAndUpdateAsync(filter, update);

            var response = _mapper.Map<AuthenticateResponse>(account);
            response.JwtToken = jwtToken;
            response.RefreshToken = refreshToken.Token;
            return response;
        }







        private string randomTokenString()
        {
            using var rngCryptoServiceProvider = new RNGCryptoServiceProvider();
            var randomBytes = new byte[40];
            rngCryptoServiceProvider.GetBytes(randomBytes);
            return BitConverter.ToString(randomBytes).Replace("-", "");
        }



        private string generateJwtToken(Account account)
        {
            var tokenHandler = new JwtSecurityTokenHandler();
            var key = Encoding.ASCII.GetBytes(_authSettings.Secret);
            var tokenDescriptor = new SecurityTokenDescriptor
            {
                Subject = new ClaimsIdentity(new[] { new Claim("id", account.Id.ToString()) }),
                Expires = DateTime.UtcNow.AddMinutes(15),
                SigningCredentials = new SigningCredentials(new SymmetricSecurityKey(key), SecurityAlgorithms.HmacSha256Signature)
            };
            var token = tokenHandler.CreateToken(tokenDescriptor);
            return tokenHandler.WriteToken(token);
        }


        private RefreshToken generateRefreshToken(string ipAddress)
        {
            return new RefreshToken
            {
                Token = randomTokenString(),
                Expires = DateTime.UtcNow.AddDays(7),
                Created = DateTime.UtcNow,
                CreatedByIp = ipAddress
            };
        }

    }
}

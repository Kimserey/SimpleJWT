namespace JWTSample

open System
open WebSharper
open WebSharper.Sitelets
open WebSharper.UI.Next
open WebSharper.UI.Next.Html
open WebSharper.UI.Next.Server
open Jose
open Newtonsoft.Json

type UserPrincipal =
    {
        Identity: UserIdentity
        Claims: string list
    }

and UserIdentity = 
    {
        Email: string
    }

type JwtPayload =
    {
        [<JsonProperty "tokenRole">]
        TokenRole: string
        [<JsonProperty "principal">]
        Principal: UserPrincipal
        [<JsonProperty "iss">]
        Issuer: string
        [<JsonProperty "sub">]
        Subject: string
        [<JsonProperty "exp">]
        Expiry: DateTime
        [<JsonProperty "iat">]
        IssuedAtTime: DateTime
        [<JsonProperty "jti">]
        Id: string
    }

[<AutoOpen>]
module Jwt =
    
    type DecodeResult =
        | Success of JwtPayload
        | Failure of DecodeError
    and DecodeError =
        /// if signature validation failed, integrity is compromised
        | IntegrityException
        /// if JWT token can't be decrypted
        | EncryptionException
        /// if JWT signature, encryption or compression algorithm is not supported
        | InvalidAlgorithmException
        | UnhandledException

    // Creates a random 256 base64 key
    let generateKey() =
        let random = new Random()
        let array: byte[] = Array.zeroCreate 256
        random.NextBytes(array)
        Convert.ToBase64String(array)

    // Server dictates the algorithm used for encode/decode to prevent vulnerability
    // https://auth0.com/blog/critical-vulnerabilities-in-json-web-token-libraries/
    let private algorithm = Jose.JwsAlgorithm.HS256

    let generate key issuer tokenRole (principal: UserPrincipal) (expiry: DateTime) =
        let payload = 
            {
                Id = Guid.NewGuid().ToString("N")
                Issuer = issuer
                Subject = principal.Identity.Email
                Expiry = expiry
                IssuedAtTime = DateTime.UtcNow
                Principal = principal
                TokenRole = tokenRole
            }
        Jose.JWT.Encode(JsonConvert.SerializeObject(payload), Convert.FromBase64String(key), algorithm)

    let decode key token =
        try
            Success <| JsonConvert.DeserializeObject<JwtPayload>(Jose.JWT.Decode(token, Convert.FromBase64String(key), algorithm))
        with
        | :? Jose.IntegrityException  -> Failure IntegrityException
        | :? Jose.EncryptionException -> Failure EncryptionException
        | :? Jose.InvalidAlgorithmException -> Failure InvalidAlgorithmException
        | _ -> Failure UnhandledException

type EndPoint =
    | [<EndPoint "/data">] Data
    | [<EndPoint "/auth">] Auth of AuthEndPoint

and AuthEndPoint =
    | [<EndPoint "POST /token"; Json "credentials">] Token of credentials: Credentials
    | [<EndPoint "POST /refresh"; Json "token">] Refresh of token: string

and Credentials =
    { Email: string
      Password: string }

type ApiContext =
    { WebContext: Context<EndPoint>
      Principal: UserPrincipal }

[<JavaScript>]
module Client =
    open WebSharper.UI.Next.Client

    let main principal =
        text <| "Hello " + principal.Identity.Email

module Site =

    let getPrivateKey() = ""

    // Fake verification
    let verify credentials = 
        true

    // Fake retrieval of principal
    let getPrincipal userId =
        { Claims = []
          Identity = { Email = "test@test.com" } }

    let authenticate (ctx: Context<_>) content =
        let result =
            ctx.Request.Headers 
            |> Seq.tryFind (fun h -> h.Name = "Authorization")
            |> Option.filter (fun h -> h.Value.StartsWith("Bearer ", StringComparison.OrdinalIgnoreCase))
            |> Option.map (fun h -> h.Value.Substring(7))
            |> Option.map (decode (getPrivateKey()))

        match result with
        | Some (DecodeResult.Success payload) ->
            // do some check on the payload like token expiry, issuer, then account locked etc..
            content { Principal = payload.Principal; WebContext = ctx }
        | _ -> Content.Unauthorized

    [<Website>]
    let Main =
        Application.MultiPage (fun ctx ->
            function
            | Data -> authenticate ctx (fun ctx -> "You are authenticated! " + ctx.Principal.Identity.Email |> Content.Json)
            | Auth endpoint ->
                match endpoint with
                | Token credentials -> 
                    if verify credentials then
                        // Credentials verified, retrieve principal
                        let principal = getPrincipal credentials.Email
                        [ Jwt.generate (getPrivateKey()) "JWTSample" "access_token" principal (DateTime.UtcNow.AddDays(1.))
                          Jwt.generate (getPrivateKey()) "JWTSample" "refresh_token" principal (DateTime.UtcNow.AddDays(7.)) ]
                        |> Content.Json
                    else Content.Unauthorized
                | Refresh refreshToken ->
                    match decode (getPrivateKey()) refreshToken with
                    | DecodeResult.Success payload ->
                        if payload.Expiry <= DateTime.UtcNow then
                            // Refresh token valid, refresh principal
                            let principal = getPrincipal payload.Principal.Identity.Email
                            [ Jwt.generate (getPrivateKey()) "JWTSample" "access_token" principal (DateTime.UtcNow.AddDays(1.))
                              Jwt.generate (getPrivateKey()) "JWTSample" "refresh_token" principal (DateTime.UtcNow.AddDays(7.)) ]
                            |> Content.Json
                        else Content.Unauthorized
                    | DecodeResult.Failure _ -> Content.Unauthorized
        )


module SelfHostedServer =

    open global.Owin
    open Microsoft.Owin.Hosting
    open Microsoft.Owin.StaticFiles
    open Microsoft.Owin.FileSystems
    open WebSharper.Owin

    [<EntryPoint>]
    let Main args =
        let rootDirectory, url =
            match args with
            | [| rootDirectory; url |] -> rootDirectory, url
            | [| url |] -> "..", url
            | [| |] -> "..", "http://localhost:9000/"
            | _ -> eprintfn "Usage: JWTSample ROOT_DIRECTORY URL"; exit 1
        use server = WebApp.Start(url, fun appB ->
            appB.UseStaticFiles(
                    StaticFileOptions(
                        FileSystem = PhysicalFileSystem(rootDirectory)))
                .UseSitelet(rootDirectory, Site.Main)
            |> ignore)
        stdout.WriteLine("Serving {0}", url)
        stdin.ReadLine() |> ignore
        0

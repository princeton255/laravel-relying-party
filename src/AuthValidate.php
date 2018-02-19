<?php

namespace OAuth2Middleware;

use Closure;
use GuzzleHttp\Client;
use Illuminate\Auth\AuthenticationException;
use Illuminate\Support\Facades\Auth;
use Illuminate\Support\Facades\Config;
use Illuminate\Support\Facades\Log;
use Lcobucci\JWT\Parser;
use Lcobucci\JWT\Signer\Rsa\Sha256;
use Lcobucci\JWT\Token;

class AuthValidate
{
    public function validateToken (Token $token)
    {
        try {
            $signer = new Sha256();

            $public_key = storage_path('oauth-public.key');

            $is_valid = $token->verify($signer, file_get_contents($public_key));
        } catch (\Exception $exception) {
            Log::debug('Exception caught during Token validation: ' . $exception->getMessage());
            return false;
        }

        return $is_valid;
    }

    public function getUserInfo ($token)
    {
        $client = new Client();
        $response = $client->get(Config::get('oauth2middleware.idp_url'),
            [
                'headers' => [
                    'Accept' => 'application/json',
                    'Authorization' => 'Bearer ' . $token,
                ],
            ]);

        return json_decode($response->getBody(), true);
    }

    /**
     * @param $request
     * @param Closure $next
     * @return mixed
     * @throws AuthenticationException
     */
    public function handle ($request, Closure $next)
    {
        /** @var \Illuminate\Http\Request $request */
        $token = $request->bearerToken();

        if (is_null($token)) {
            Log::debug('No Bearer Token found in request');
            throw new AuthenticationException();
        }

        $token = (new Parser())->parse((string)$token); // Parses from a string

        if (!$this->validateToken($token)) {
            Log::debug('Invalid Bearer token supplied');
            throw new AuthenticationException();
        }

        //check user exists
        $user_id = $token->getClaim('sub');

        $user = User::find($user_id);

        if ($user === null) {
            // User does not exist in our database
            // Check if user has admin role to create
            // new company for the user.

            $user_info = $this->getUserInfo($request->bearerToken());
            $user = User::create($user_info);
        }

        Auth::setUser($user); // Set Current logged in User in Auth Guard for access in controllers

        return $next($request);
    }
}

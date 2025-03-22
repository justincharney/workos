<?php

namespace Laravel\WorkOS\Http\Requests;

use Illuminate\Foundation\Http\FormRequest;
use Illuminate\Support\Facades\Auth;
use Inertia\Inertia;
use Laravel\WorkOS\WorkOS;
use Illuminate\Http\JsonResponse;
use WorkOS\UserManagement;

class AuthKitLogoutRequest extends FormRequest
{
    /**
     * Redirect the user to WorkOS for authentication.
     */
    public function logout(): JsonResponse
    {
        $accessToken = $this->session()->get("workos_access_token");

        $workOsSession = $accessToken
            ? WorkOS::decodeAccessToken($accessToken)
            : false;

        Auth::guard("web")->logout();

        $this->session()->invalidate();
        $this->session()->regenerateToken();

        if (!$workOsSession) {
            return response()->json(
                ["message" => "Logged out successfully."],
                200
            );
        }

        $logoutUrl = (new UserManagement())->getLogoutUrl(
            $workOsSession["sid"]
        );

        return response()->json(
            [
                "message" => "Logged out successfully.",
                "logout_url" => $logoutUrl,
            ],
            200
        );
    }
}

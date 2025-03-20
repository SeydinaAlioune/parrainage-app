<?php

namespace App\Http\Middleware;

use Closure;
use Illuminate\Session\TokenMismatchException;
use Illuminate\Support\Facades\Session;

class VerifyCsrfMiddleware
{
    public function handle($request, Closure $next)
    {
        if (!$request->is('login') || !$request->isMethod('post')) {
            return $next($request);
        }

        if (!Session::has('_token')) {
            Session::regenerateToken();
        }

        $token = $request->input('_token') ?: $request->header('X-CSRF-TOKEN');

        if (!$token || $token !== Session::token()) {
            Session::regenerateToken();
            return redirect()->back()->with('error', 'Session expirée. Veuillez réessayer.');
        }

        return $next($request);
    }
}

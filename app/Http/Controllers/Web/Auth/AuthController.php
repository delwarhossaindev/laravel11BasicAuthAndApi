<?php

namespace App\Http\Controllers\Web\Auth;

use App\Http\Controllers\Controller;
use Illuminate\Http\Request;
use Illuminate\Support\Facades\Auth;
use Illuminate\Support\Facades\Hash;
use Illuminate\Support\Facades\Session;
use App\Models\User;
use Illuminate\View\View;
use Illuminate\Http\RedirectResponse;

class AuthController extends Controller
{
    /**
     * Display login form.
     *
     * @return View
     */
    public function index(): View
    {
        return view('auth.login');
    }

    /**
     * Display registration form.
     *
     * @return View
     */
    public function registration(): View
    {
        return view('auth.registration');
    }

    /**
     * Handle login request.
     *
     * @param Request $request
     * @return RedirectResponse
     */
    public function postLogin(Request $request): RedirectResponse
    {
        // Validate login credentials
        $request->validate([
            'email' => 'required|email',
            'password' => 'required|min:6',
        ]);

        // Attempt login with provided credentials
        $credentials = $request->only('email', 'password');
        if (Auth::attempt($credentials)) {
            // Redirect to the intended page or dashboard if successful
            return redirect()->intended('dashboard')->withSuccess('You have successfully logged in.');
        }

        // Redirect back with error if login fails
        return redirect()->route('login')->withErrors('Oops! You have entered invalid credentials.');
    }

    /**
     * Handle registration request.
     *
     * @param Request $request
     * @return RedirectResponse
     */
    public function postRegistration(Request $request): RedirectResponse
    {
        // Validate registration data
        $request->validate([
            'name' => 'required|string|max:255',
            'email' => 'required|email|unique:users,email',
            'password' => 'required|string|min:6|confirmed',
        ]);

        // Create a new user
        $user = $this->create($request->all());

        // Automatically log in the new user
        Auth::login($user);

        // Redirect to the dashboard after successful registration
        return redirect('dashboard')->withSuccess('Great! You have successfully registered and logged in.');
    }

    /**
     * Display the dashboard.
     *
     * @return View|RedirectResponse
     */
    public function dashboard(): View|RedirectResponse
    {
        // Check if the user is authenticated
        if (Auth::check()) {
            return view('welcome'); // Change to your dashboard view as necessary
        }

        // Redirect to login if the user is not authenticated
        return redirect()->route('login')->withErrors('Oops! You do not have access.');
    }

    /**
     * Create a new user.
     *
     * @param array $data
     * @return User
     */
    protected function create(array $data): User
    {
        return User::create([
            'name' => $data['name'],
            'email' => $data['email'],
            'password' => Hash::make($data['password']),
        ]);
    }

    /**
     * Log the user out and invalidate the session.
     *
     * @return RedirectResponse
     */
    public function logout(): RedirectResponse
    {
        // Clear session data and log the user out
        Session::flush();
        Auth::logout();

        // Redirect to the login page
        return redirect()->route('login');
    }
}

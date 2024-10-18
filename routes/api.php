<?php

use Illuminate\Support\Facades\Route;
use App\Http\Controllers\Api\Auth\PermissionsController;
use App\Http\Controllers\Api\Auth\RolesController;
use App\Http\Controllers\Api\Auth\UserController;

// Public Routes
Route::post('/register', [UserController::class, 'register']);
Route::post('/login', [UserController::class, 'login']);

// Protected Routes
Route::middleware(['auth:sanctum'])->group(function () {
    Route::post('/logout', [UserController::class, 'logout']);
    Route::get('/loggeduser', [UserController::class, 'logged_user']);
    Route::post('/changepassword', [UserController::class, 'change_password']);

    // User List
    Route::get('/role_list', [UserController::class, 'role_list']);
    Route::get('/permission_list', [UserController::class, 'permission_list']);
    Route::get('/user_list', [UserController::class, 'user_list']);

    // User Show
    Route::get('/user_show/{id}', [UserController::class, 'show']);

    // User Update
    Route::get('/user_edit/{id}', [UserController::class, 'user_edit']);
    Route::put('/user_update/{id}', [UserController::class, 'user_update']);

    // User Delete
    Route::delete('/user_delete/{id}', [UserController::class, 'user_delete']);

    // Assign Permission
    Route::put('/assign_permission/{id}', [UserController::class, 'assign_permission']);

    // Roles and Permissions
    Route::resource('roles', RolesController::class);
    Route::get('/role_wise_user', [UserController::class, 'role_wise_user']);
    Route::resource('permissions', PermissionsController::class);
});

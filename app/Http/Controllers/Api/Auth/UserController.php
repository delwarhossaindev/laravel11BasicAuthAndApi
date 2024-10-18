<?php

namespace App\Http\Controllers\Api\Auth;

use App\Http\Controllers\Controller;
use App\Models\User;
use Illuminate\Http\Request;
use Illuminate\Support\Facades\DB;
use Illuminate\Support\Facades\Hash;
use Illuminate\Support\Facades\Validator;
use Spatie\Permission\Models\Permission;
use Spatie\Permission\Models\Role;

class UserController extends Controller
{
    public function register(Request $request)
    {
        $validated = Validator::make($request->all(), [
            'name' => 'required',
            'email' => 'required|email|unique:users',
            'password' => 'required|confirmed',
            // Make roles optional
            'roles' => 'sometimes|exists:roles,name',
        ]);

        if ($validated->fails()) {
            return response([
                'message' => $validated->errors(),
                'status' => 'error',
            ], 422);
        }

        DB::beginTransaction();
        try {
            $user = User::create([
                'name' => $request->name,
                'email' => $request->email,
                'password' => Hash::make($request->password),
            ]);

            // Assign role if roles is provided
            if ($request->has('roles') && $request->roles) {
                $user->assignRole($request->roles);
            }

            $token = $user->createToken($request->email)->plainTextToken;
            DB::commit();

            return response([
                'token' => $token,
                'message' => 'Registration Success',
                'status' => 'success',
            ], 201);
        } catch (\Exception $e) {

            DB::rollback();
            return response([
                "message" => "Something went wrong, please try again later.",
                "status" => "error",
            ], 500);
        }
    }


    public function login(Request $request)
    {
        try {
            // Validate request data
            $request->validate([
                'email' => 'required|email',
                'password' => 'required',
            ]);

            $user = User::where('email', $request->email)->first();

            if ($user && Hash::check($request->password, $user->password)) {
                $token = $user->createToken($request->email)->plainTextToken;

                return response()->json([
                    'token' => $token,
                    'message' => 'Login Success',
                    'status' => 'success',
                ], 200);
            }

            return response()->json([
                'message' => 'The provided credentials are incorrect',
                'status' => 'failed',
            ], 401);
        } catch (\Exception $e) {
            return response()->json([
                'message' => 'An error occurred: ' . $e->getMessage(),
                'status' => 'error',
            ], 500);
        }
    }

    public function logout()
    {
        try {
            // Delete all tokens for the logged-in user
            auth()->user()->tokens()->delete();

            return response()->json([
                'message' => 'Logout Success',
                'status' => 'success',
            ], 200);
        } catch (\Exception $e) {
            return response()->json([
                'message' => 'Error logging out: ' . $e->getMessage(),
                'status' => 'error',
            ], 500);
        }
    }

    public function logged_user()
    {
        try {
            $loggedUser = auth()->user();

            // Get extra permissions
            $extraPermissions = collect($loggedUser->permissions)->pluck("name");

            $permissionsList = collect();

            // Check if the user has roles
            if ($loggedUser->roles->isNotEmpty()) {
                $roleIDs = $loggedUser->roles->pluck('id');

                // Retrieve role permissions
                $rolePermissions = Permission::join('role_has_permissions', 'role_has_permissions.permission_id', '=', 'permissions.id')
                    ->whereIn('role_has_permissions.role_id', $roleIDs)
                    ->get();

                $permissionsList = collect($rolePermissions)->pluck('name')
                    ->merge($extraPermissions)
                    ->unique();
            }

            return response()->json([
                'user' => $loggedUser,
                'permissions_list' => $permissionsList,
                'message' => 'Logged User Data',
                'status' => 'success',
            ], 200);
        } catch (\Exception $e) {
            return response()->json([
                'message' => 'Error retrieving logged user data: ' . $e->getMessage(),
                'status' => 'error',
            ], 403);
        }
    }


    public function change_password(Request $request)
    {
        $request->validate([
            'password' => 'required|string|min:8|confirmed', // Added confirmation and length validation
        ]);

        try {
            $loggedUser = auth()->user();
            $loggedUser->password = Hash::make($request->password);
            $loggedUser->save(); // Use save() instead of update() for a new model instance

            return response()->json([
                'message' => 'Password Changed Successfully',
                'status' => 'success',
            ], 200);
        } catch (\Exception $e) {
            return response()->json([
                'message' => 'Error changing password',
                'status' => 'error',
                'error' => $e->getMessage(),
            ], 500);
        }
    }


    public function role_list()
    {
        try {
            $roles = Role::pluck('name', 'id')->all();

            return response()->json([
                'roles' => $roles,
                'message' => 'All Role List',
                'status' => 'success',
            ], 200);
        } catch (\Exception $e) {
            return response()->json([
                'message' => 'Error fetching role list',
                'status' => 'error',
                'error' => $e->getMessage(),
            ], 500);
        }
    }


    public function role_wise_user()
    {
        try {
            $data = DB::table('users as user')
                ->select('user.id as user_id', 'user.email', 'user.name', 'r.name as role_name')
                ->join('model_has_roles as mhr', 'user.id', '=', 'mhr.model_id')
                ->join('roles as r', 'mhr.role_id', '=', 'r.id')
                ->get();

            // Group users by role name
            $roles = $data->groupBy('role_name');

            return response()->json([
                'roles' => $roles,
                'message' => 'Role Wise User List',
                'status' => 'success',
            ], 200);
        } catch (\Exception $e) {
            return response()->json([
                'message' => 'Error fetching role wise user list',
                'status' => 'error',
                'error' => $e->getMessage(),
            ], 500);
        }
    }


    public function permission_list()
    {
        try {
            $permissions = Permission::select('name', 'id')->get();

            return response()->json([
                'permissions' => $permissions,
                'message' => 'All Permission List',
                'status' => 'success',
            ], 200);
        } catch (\Exception $e) {
            return response()->json([
                'message' => 'Error fetching permission list',
                'status' => 'error',
                'error' => $e->getMessage(),
            ], 500);
        }
    }

    public function user_list()
    {
        try {
            // Eager load roles and permissions
            $userList = User::with(['roles', 'permissions'])->get();

            // Optionally transform the user data if needed
            $userList = $userList->map(function ($data) {
                return [
                    'id' => $data->id,
                    'name' => $data->name,
                    'roles' => $data->roles,
                    'permissions' => $data->permissions,
                ];
            });

            return response()->json([
                'users' => $userList,
                'message' => 'All User List',
                'status' => 'success'
            ], 200);
        } catch (\Exception $e) {
            return response()->json([
                'message' => 'Error fetching user list',
                'status' => 'error',
                'error' => $e->getMessage(),
            ], 500);
        }
    }


    public function user_edit(string $id)
    {
        try {
            // Eager load roles and permissions
            $userList = User::with(['roles', 'permissions'])->find($id);

            // Handle case where user is not found
            if (!$userList) {
                return response([
                    'message' => 'User not found',
                    'status' => 'error',
                ], 404);
            }

            return response([
                'user_info' => $userList,
                'message' => 'User Edit Info',
                'status' => 'success',
            ], 200);
        } catch (\Exception $e) {
            return response([
                "message" => "Something went wrong: " . $e->getMessage(),
                "status" => "error",
            ], 500);
        }
    }


    public function user_update(Request $request, string $id)
    {
        // Validate input data
        $validated = Validator::make($request->all(), [
            "name" => "required",
            "email" => "required|email|unique:users,email," . $id,
            "status" => "sometimes|in:active,inactive", // Add validation for status
            "roles" => "sometimes|exists:roles,name",   // Validate if roles are provided
        ]);

        if ($validated->fails()) {
            return response(
                [
                    "message" => $validated->errors(),
                    "status" => "error",
                ],
                422
            );
        }

        DB::beginTransaction();
        try {
            $user = User::find($id);

            // Check if the user exists
            if (!$user) {
                return response(
                    [
                        "message" => "User Not Found",
                        "status" => "error",
                    ],
                    404
                );
            }

            // Update user details
            $user->update([
                "name" => $request->name,
                "email" => $request->email,
                "status" => $request->status,
            ]);

            // Sync roles if provided
            if ($request->has('roles')) {
                $user->syncRoles($request->roles);
            }

            DB::commit();

            // Return updated user information
            return response(
                [
                    "user" => $user->load('roles'),  // Load roles after update
                    "message" => "User updated successfully",
                    "status" => "success",
                ],
                200
            );
        } catch (\Exception $e) {
            DB::rollback();
            return response(
                [
                    "message" => "An error occurred: " . $e->getMessage(),
                    "status" => "error",
                ],
                500
            );
        }
    }


    public function assign_permission(Request $request, $id)
    {
        // Validate input data
        $validated = Validator::make($request->all(), [
            "permissions" => "required|array", // Ensure permissions is an array
            "permissions.*" => "exists:permissions,name", // Validate each permission exists
        ]);

        if ($validated->fails()) {
            return response(
                [
                    "message" => $validated->errors(),
                    "status" => "error",
                ],
                422
            );
        }

        DB::beginTransaction();
        try {
            $user = User::find($id);

            // Check if the user exists
            if (!$user) {
                return response(
                    [
                        "message" => "User not found!",
                        "status" => "error",
                    ],
                    404
                );
            }

            // Assign permissions to the user
            $user->syncPermissions($request->permissions);

            DB::commit();

            // Return the user's updated permissions
            return response(
                [
                    "permissions" => $user->permissions,  // Return assigned permissions
                    "message" => "Permissions assigned successfully",
                    "status" => "success",
                ],
                200
            );
        } catch (\Exception $e) {
            DB::rollback();
            return response(
                [
                    "message" => "An error occurred: " . $e->getMessage(),
                    "status" => "error",
                ],
                500
            );
        }
    }

    public function show(string $id)
    {
        try {
            // Eager load roles and permissions
            $userList = User::with(['roles', 'permissions'])->find($id);

            // Handle case where user is not found
            if (!$userList) {
                return response([
                    'message' => 'User not found',
                    'status' => 'error',
                ], 404);
            }

            return response([
                'user_info' => $userList,
                'message' => 'User Info',
                'status' => 'success',
            ], 200);
        } catch (\Exception $e) {
            return response([
                "message" => "Something went wrong: " . $e->getMessage(),
                "status" => "error",
            ], 500);
        }
    }


    public function user_delete(string $id)
    {
        DB::beginTransaction();
        try {
            $user = User::find($id);

            // Check if the user exists
            if (!$user) {
                return response(
                    [
                        "message" => "User not found!",
                        "status" => "error",
                    ],
                    404
                );
            }

            // Delete the user
            $user->delete();

            DB::commit();
            return response(
                [
                    "message" => "User deleted successfully",
                    "status" => "success",
                ],
                200
            );
        } catch (\Exception $e) {
            DB::rollback();
            return response(
                [
                    "message" => "An error occurred: " . $e->getMessage(),
                    "status" => "error",
                ],
                500
            );
        }
    }

}

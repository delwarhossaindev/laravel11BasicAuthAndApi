<?php

namespace App\Http\Controllers\Api\Auth;

use Illuminate\Http\Request;
use Illuminate\Support\Facades\DB;
use Spatie\Permission\Models\Role;
use App\Http\Controllers\Controller;
use Spatie\Permission\Models\Permission;
use Illuminate\Support\Facades\Validator;

class RolesController extends Controller
{

    public function index(Request $request)
    {
        try {
            $roles = Role::with('permissions')->get();

            return response([
                'role' => $roles,
                'message' => 'All Roles List',
                'status' => 'Success'
            ], 200);
        } catch (\Exception $e) {
            return response([
                "message" => $e->getMessage(),
                "status" => "error",
            ], 403);
        }
    }


    public function create()
    {
        try {
            $permissions = Permission::get();
            return response([
                'permissions' => $permissions,
                'message' => 'Create Successfully',
                'status' => 'Success'
            ], 200);
        } catch (\Exception $e) {
            return response([
                "message" => $e->getMessage(),
                "status" => "error",
            ], 403);
        }
    }


    public function store(Request $request)
    {
        // Validate the request input
        $validated = Validator::make($request->all(), [
            'name' => 'required|unique:roles,name',
            'permission' => 'required|array',
            'permission.*' => 'exists:permissions,name', // Ensure each permission name exists in the permissions table
        ], [
            'name.unique' => 'The role name already exists. Please choose a different name.',
            'permission.*.exists' => 'One or more permissions do not exist. Please check the permission names.',
        ]);

        if ($validated->fails()) {
            return response([
                'message' => $validated->errors(),
                'status' => 'error'
            ], 400); // 400 Bad Request
        }

        // Begin database transaction
        DB::beginTransaction();
        try {
            // Create a new role and sync permissions
            $role = Role::create([
                'name' => $request->get('name'),
                'guard_name' => 'web'
            ]);
            $role->syncPermissions($request->permission);

            // Commit the transaction
            DB::commit();

            // Return a successful response
            return response([
                'role' => $role,
                'message' => 'Role created successfully',
                'status' => 'success'
            ], 201); // 201 Created
        } catch (\Exception $e) {
            // Rollback transaction on error
            DB::rollback();

            // Return an error response
            return response([
                "message" => $e->getMessage(),
                "status" => "error",
            ], 403); // 403 Internal Server Error
        }
    }



    public function show(Role $role)
    {
        try {
            $rolePermissions = $role->permissions;

            return response([
                'role' => $role,
                'permissions' => $rolePermissions,
                'message' => 'Role Individual Show',
                'status' => 'Success'
            ], 200);
        } catch (\Exception $e) {
            return response([
                "message" => $e->getMessage(),
                "status" => "error",
            ], 403);
        }
    }


    public function edit(string $id)
    {
        try {
            $role = Role::with('permissions')->findOrFail($id);

            return response([
                'role' => $role,
                'message' => 'Role Individual Edit',
                'status' => 'Success'
            ], 200);
        } catch (\Exception $e) {
            return response([
                "message" => $e->getMessage(),
                "status" => "error",
            ], 403);
        }
    }


    public function update($id, Request $request)
    {
        DB::beginTransaction();
        try {
            // Validate the request input
            $validated = Validator::make($request->all(), [
                'name' => 'required|unique:roles,name,' . $id, // Ensure the name is unique, excluding the current role
                'permission' => 'required|array', // Ensure permissions are passed as an array
                'permission.*' => 'exists:permissions,name', // Validate that each permission name exists
            ], [
                'name.unique' => 'The role name already exists. Please choose a different name.',
                'permission.*.exists' => 'One or more permissions do not exist. Please check the permission names.',
            ]);

            if ($validated->fails()) {
                return response([
                    'message' => $validated->errors(),
                    'status' => 'error'
                ], 400); // 400 Bad Request
            }

            $role = Role::findOrFail($id); // Use findOrFail to handle not found
            $role->update($request->only('name')); // Update the role's name
            $role->syncPermissions($request->get('permission')); // Sync the permissions
            DB::commit(); // Commit the transaction

            return response([
                'role' => Role::with('permissions')->findOrFail($id), // Return the updated role with permissions
                'message' => 'Role updated successfully',
                'status' => 'success' // Use lowercase 'success'
            ], 200); // 200 OK
        } catch (\Exception $e) {
            DB::rollback(); // Rollback transaction on error
            return response([
                "message" => $e->getMessage(),
                "status" => "error",
            ], 403); // 403 Internal Server Error
        }
    }


    public function destroy($id)
    {
        try {
            $role = Role::findOrFail($id); // Use findOrFail to handle not found
            $role->delete();

            return response([
                'message' => 'Role deleted successfully',
                'status' => 'Success'
            ], 200);
        } catch (\Exception $e) {
            return response([
                "message" => $e->getMessage(),
                "status" => "error",
            ], 403);
        }
    }
}

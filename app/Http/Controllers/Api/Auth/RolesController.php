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
        $validated = Validator::make($request->all(), [
            'name' => 'required|unique:roles,name',
            'permission' => 'required|array', // Ensure permissions are passed as an array
        ]);

        if ($validated->fails()) {
            return response([
                'message' => $validated->errors(),
                'status' => 'error'
            ], 400); // Use 400 for bad request
        }

        DB::beginTransaction();
        try {
            $role = Role::create(['name' => $request->get('name'), 'guard_name' => 'web']);
            $role->syncPermissions($request->permission);
            DB::commit();
            return response([
                'role' => $role,
                'message' => 'Role created successfully',
                'status' => 'Success'
            ], 201); // Use 201 for resource created
        } catch (\Exception $e) {
            DB::rollback();
            return response([
                "message" => $e->getMessage(),
                "status" => "error",
            ], 500); // Use 500 for server error
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
            $validated = Validator::make($request->all(), [
                'name' => 'required',
                'permission' => 'required|array', // Ensure permissions are passed as an array
            ]);

            if ($validated->fails()) {
                return response([
                    'message' => $validated->errors(),
                    'status' => 'error'
                ], 400); // Use 400 for bad request
            }

            $role = Role::findOrFail($id); // Use findOrFail to handle not found
            $role->update($request->only('name'));
            $role->syncPermissions($request->get('permission'));
            DB::commit();

            return response([
                'role' => Role::with('permissions')->findOrFail($id),
                'message' => 'Role updated successfully',
                'status' => 'Success'
            ], 200);
        } catch (\Exception $e) {
            DB::rollback();
            return response([
                "message" => $e->getMessage(),
                "status" => "error",
            ], 500); // Use 500 for server error
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

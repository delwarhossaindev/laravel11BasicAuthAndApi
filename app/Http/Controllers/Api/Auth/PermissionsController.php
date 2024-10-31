<?php

namespace App\Http\Controllers\Api\Auth;

use App\Http\Controllers\Controller;
use Illuminate\Http\Request;
use Spatie\Permission\Models\Permission;
use Illuminate\Support\Facades\Validator;

class PermissionsController extends Controller
{
    /**
     * Display a listing of the resource.
     *
     * @return \Illuminate\Http\Response
     */
    public function index()
    {
        try {
            $permissions = Permission::all();

            return response([
                'permissions' => $permissions,
                'message' => 'All Permission List',
                'status' => 'Success'
            ], 200);

        } catch (\Exception $e) {
            return response([
                'message' => $e->getMessage(),
                'status' => 'Error'
            ], 403);
        }
    }

    /**
     * Display the specified resource.
     *
     * @param  int  $id
     * @return \Illuminate\Http\Response
     */
    public function show($id)
    {
        try {
            $permission = Permission::find($id);

            if (!$permission) {
                return response([
                    'message' => 'Permission Not Found',
                    'status' => 'Error',
                ], 403);
            }

            return response([
                'permission' => $permission,
                'message' => 'Permission Details',
                'status' => 'Success',
            ], 200);

        } catch (\Exception $e) {
            return response([
                'message' => $e->getMessage(),
                'status' => 'Error',
            ], 403);
        }
    }


    /**
     * Store a newly created resource in storage.
     *
     * @param  \Illuminate\Http\Request  $request
     * @return \Illuminate\Http\Response
     */
    public function store(Request $request)
    {
        $request->validate([
            'name' => 'required|unique:permissions,name'
        ]);

        try {
            $permission = Permission::create(['name' => $request->get('name'), 'guard_name' => 'web']);

            return response([
                'permission' => $permission,
                'message' => 'Permission created successfully',
                'status' => 'Success'
            ], 201);

        } catch (\Exception $e) {
            return response([
                'message' => $e->getMessage(),
                'status' => 'Error'
            ], 403);
        }
    }

    /**
     * Show the form for editing the specified resource.
     *
     * @param  int  $id
     * @return \Illuminate\Http\Response
     */
    public function edit($id)
    {
        try {
            $permission = Permission::find($id);

            if (!$permission) {
                return response([
                    'message' => 'Permission Not Found',
                    'status' => 'Error'
                ], 403);
            }

            return response([
                'permission' => $permission,
                'message' => 'Permission Individual Edit',
                'status' => 'Success',
            ], 200);

        } catch (\Exception $e) {
            return response([
                'message' => $e->getMessage(),
                'status' => 'Error'
            ], 403);
        }
    }

    /**
     * Update the specified resource in storage.
     *
     * @param  int  $id
     * @param  \Illuminate\Http\Request  $request
     * @return \Illuminate\Http\Response
     */
    public function update($id, Request $request)
    {
        $validator = Validator::make($request->all(), [
            'name' => 'required|unique:permissions,name,' . $id
        ]);

        if ($validator->fails()) {
            return response([
                'message' => $validator->errors(),
                'status' => 'Error',
            ], 422);
        }

        try {
            $permission = Permission::find($id);

            if (!$permission) {
                return response([
                    'message' => 'Permission Not Found',
                    'status' => 'Error',
                ], 403);
            }

            $permission->update($request->only('name'));

            return response([
                'permission' => $permission,
                'message' => 'Permission updated successfully',
                'status' => 'Success',
            ], 200);

        } catch (\Exception $e) {
            return response([
                'message' => $e->getMessage(),
                'status' => 'Error',
            ], 403);
        }
    }

    /**
     * Remove the specified resource from storage.
     *
     * @param  int  $id
     * @return \Illuminate\Http\Response
     */
    public function destroy($id)
    {
        try {
            $permission = Permission::find($id);

            if (!$permission) {
                return response([
                    'message' => 'Permission Not Found',
                    'status' => 'Error',
                ], 403);
            }

            $permission->delete();

            return response([
                'message' => 'Permission deleted successfully',
                'status' => 'Success',
            ], 200);

        } catch (\Exception $e) {
            return response([
                'message' => $e->getMessage(),
                'status' => 'Error',
            ], 403);
        }
    }
}

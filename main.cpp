#include "utils.hpp"

std::string g_session;
websocket_t::self_ptr g_client;

HANDLE g_process = nullptr;
void* g_image_base = nullptr;

struct loader_data {
    uint32_t base = 0;
    uint32_t entry = 0;
};

DWORD __stdcall internal_loader( loader_data* data ) {
    using dll_entry_t = BOOL ( __stdcall* ) ( uint32_t, uint32_t, uint32_t );
    ( reinterpret_cast< dll_entry_t >( data->entry ) )( data->base, DLL_PROCESS_ATTACH, 0 );
    return 1;
}

DWORD __stdcall internal_stub( ) {
    return 1;
}

void handle_message( const std::string& message, void* user_data ) {
    nlohmann::json data;
    nlohmann::json response;

    try {
        std::stringstream( message ) >> data;
    } catch ( ... ) {
        return;
    }

    if ( !data.contains( "type" ) || !data.at( "type" ).is_number_unsigned( ) )
        return;

    switch ( data.at( "type" ).get< uint32_t >( ) ) {
    case 0: {
        g_session = data.at( "session_id" ).get< std::string >( );

        printf( "session id - %s\n", g_session.c_str( ) );

        response[ "username" ] = "some_name";
        response[ "password" ] = "pass123";
        break;
    }
    case 1: {
        if ( data.at( "status" ).get< uint32_t >( ) != 0 ) {
            printf( "failed to auth, incorrect credentials or no sub on account" );
            return;
        }
        
        std::ifstream mapfile_stream( "D:\\hello-world.map" );
        std::stringstream map_stream;
        map_stream << mapfile_stream.rdbuf( );
        mapfile_stream.close( );
        
        std::vector< uint8_t > pe_binary = { };
        open_binary( "D:\\hello-world.dll", pe_binary );

        response[ "map" ] = map_stream.str( );
        response[ "pe" ] = pe_binary;
        response[ "settings" ][ "shuffle" ] = true;

        break;
    }
    case 2: {
        if ( data.at( "status" ).get< uint32_t >( ) != 0 ) {
            printf( "failed to initialize, status - 0x%X\n", data.at( "status" ).get< uint32_t >( ) );
            return;
        }

        printf( "successfully initialized!\n" );
        break;
    }
    case 3: {
        auto init_data = data.at( "data" ).get< nlohmann::json::object_t >( );

        g_image_base = VirtualAllocEx( g_process, nullptr, init_data.at( "size" ).get< SIZE_T >( ),
            MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE );
        if ( !g_image_base ) {
            printf( "failed to allocate memory!\n" );
            return;
        }

        response[ "data" ][ "base" ] = reinterpret_cast< uint32_t >( g_image_base );
        for ( const auto& module_info : init_data.at( "imports" ).get< nlohmann::json::object_t >( ) ) {
            auto module_base = load_dependency( module_info.first );
            if ( !module_base ) {
                printf( "failed to load dependency - %s\n", module_info.first.c_str( ) );
                return;
            }

            for ( const auto& function : module_info.second.get< nlohmann::json::array_t >( ) ) {
                auto remote_function = get_remote_pointer( module_info.first, function.get< std::string >( ) );
                if ( !remote_function ) {
                    printf( "[%s] unable to find %s export\n", module_info.first.c_str( ), function.get< std::string >( ).c_str( ) );
                    return;
                }

                response[ "data" ][ "imports" ][ module_info.first ][ function.get< std::string >( ) ] = ( uint32_t ) remote_function;
            }
        }
        
        break;
    }
    case 4: {
        auto pe_bin = data.at( "pe_bin" ).get< std::vector< uint8_t > >( );
        WriteProcessMemory( g_process, g_image_base, pe_bin.data( ), pe_bin.size( ), nullptr );
            
        g_client->close( );

        loader_data launch_data;
        launch_data.base = ( uint32_t ) g_image_base;
        launch_data.entry = data.at( "data" ).at( "entry" ).get< uint32_t >( );

        auto stub = VirtualAllocEx( g_process, nullptr, 0x1000, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE );
        if ( !stub ) {
            printf( "failed to allocate stub\n" );
            return;
        }
        
        printf( "image base - 0x%p\n", g_image_base );
        printf( "entry - 0x%X\n", launch_data.entry );

        WriteProcessMemory( g_process, stub, &launch_data, sizeof( loader_data ), nullptr );
        WriteProcessMemory( g_process, ( PVOID )( ( loader_data* ) stub + 1 ), ( LPCVOID ) internal_loader, 
            ( uint32_t ) internal_stub - ( uint32_t ) internal_loader, nullptr );

        DWORD thread_id = 0;

        auto thread = CreateRemoteThread( g_process, 0, 0, reinterpret_cast< LPTHREAD_START_ROUTINE >( ( loader_data* ) stub + 1 ), stub, 0, &thread_id );
        if ( !thread ) {
            printf( "failed to start thread\n" );
            return;
        }
        
        printf( "thread id - 0x%X\n", thread_id );

        WaitForSingleObject( thread, INFINITE );
        printf( "launched!\n" );

        break;
    }
    }
    
    response[ "session" ] = g_session;
    response[ "type" ] = data.at( "type" ).get< uint32_t >( );
    
    g_client->send( response.dump( ) );
}

int main( ) {
    auto process_id = GetPID( L"sample.exe" );
    if ( !process_id ) {
        printf( "failed to find process id\n" );
        return 1;
    }

    g_process = OpenProcess( PROCESS_ALL_ACCESS, 0, process_id );
    if ( !g_process ) {
        printf( "failed to open process handle\n" );
        return 2;
    }

    WSADATA wsa_data;
    if ( WSAStartup( MAKEWORD( 2, 2 ), &wsa_data ) ) {
        printf( "WSAStartup Failed.\n" );
        return 1;
    }

    g_client = websocket_t::new_instance( "wss://pzm322.com/ws/mutator/" );
    while ( g_client->get_state( ) != ws_invactive ) {
        g_client->poll( [ ] ( ws_error_t* error ) -> void {
                printf( "error occured - %s\n", error->message.c_str( ) );
            } );
        g_client->dispatch( handle_message );
    }

    return 0;
}

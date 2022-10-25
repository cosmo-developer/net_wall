
#include <iostream>
#include <net_wall.h>
#include <windows.devices.wifi.h>
int main()
{
    net_wall::net_wall* wall=NULL;
    try {
        std::cout << (net_wall::Init() == true ? "Success" : throw net_wall::permission_denied("COM Initialization failed")) << std::endl;
        net_wall::Intialize(&wall,FWProfile::__ALL);
		net_wall::SetEnabled(wall,false);
    }
    catch (net_wall::permission_denied& pm) {
        std::cerr << pm.what << std::endl;
        net_wall::Cleanup(wall);
    }
    net_wall::Free();
    return 0;
}

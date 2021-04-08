
#include <iostream>
#include "netmanager.h"
int main()
{
    net_wall::net_list_manager* manager;
    net_wall::net_wall* wall;
    std::cout << (net_wall::Init()==true?"Success":"Oops")<<std::endl;
    try {
        net_wall::Initialize(&wall, net_wall::FWProfile::__PUBLIC);
        net_wall::InitializeNetListManager(&manager);

        net_wall::Cleanup(manager);
        std::cout << net_wall::IsEnabled(wall) << std::endl;
        net_wall::Cleanup(wall);
    }
    catch (net_wall::permission_denied& pm) {
        std::cerr << pm.what << std::endl;
    }
    net_wall::Free();
    return 0;
}

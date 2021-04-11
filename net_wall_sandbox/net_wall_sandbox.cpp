
#include <iostream>
#include <net_wall.h>
int main()
{
    net_wall::net_wall* wall=NULL;
    net_wall::net_wall_rule* rule=NULL;
    try {
        std::cout << (net_wall::Init() == true ? "Success" : throw net_wall::permission_denied("COM Initialization failed")) << std::endl;
        net_wall::Initialize(&wall, net_wall::FWProfile::__PUBLIC);
        net_wall::GetRule("QLang", wall, &rule);
        net_wall::FWProfile profiles = net_wall::GetProfile(rule);
        std::cout << (short)profiles << std::endl;
        std::cout << (profiles == (net_wall::__PUBLIC | net_wall::__PRIVATE |net_wall::__DOMAIN)) << std::endl;
        net_wall::SetProfile(rule, net_wall::FWProfile(net_wall::__PUBLIC|net_wall::__PRIVATE|net_wall::__DOMAIN));
        net_wall::Cleanup(rule);
        net_wall::Cleanup(wall);
    }
    catch (net_wall::permission_denied& pm) {
        std::cerr << pm.what << std::endl;
        net_wall::Cleanup(wall);
    }
    net_wall::Free();
    return 0;
}

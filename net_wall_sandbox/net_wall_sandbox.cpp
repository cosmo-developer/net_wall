
#include <iostream>
#include "net_wall.h"

int main()
{
    net_wall::net_wall* nwall;

    net_wall::Initialize(&nwall,net_wall::FWProfile::__ALL);
    std::cout << net_wall::IsEnabled(nwall) << std::endl;
    net_wall::SetEnabled(nwall, false);
    std::cout << net_wall::IsEnabled(nwall) << std::endl;
    std::cout << (net_wall::GetProfile(nwall) == net_wall::FWProfile::__PUBLIC )<< std::endl;
    net_wall::Cleanup(nwall);
}

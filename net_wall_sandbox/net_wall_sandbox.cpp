
#include <iostream>
#include "net_wall.h"

int main()
{
    net_wall nwall;

    net_wall::Initialize(&nwall,FWProfile::__PUBLIC);
    std::cout << net_wall::IsEnabled(&nwall) << std::endl;
    net_wall::SetEnabled(&nwall, false);
    std::cout << net_wall::IsEnabled(&nwall) << std::endl;
    net_wall::Cleanup(&nwall);
}

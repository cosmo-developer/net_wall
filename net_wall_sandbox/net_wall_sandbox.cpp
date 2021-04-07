
#include <iostream>
#include "net_wall.h"

int main()
{
    net_wall nwall;

    Initialize(&nwall,FWProfile::__PUBLIC);
    std::cout << IsEnabled(&nwall) << std::endl;
    SetEnabled(&nwall, false);
    std::cout << IsEnabled(&nwall) << std::endl;
    Cleanup(&nwall);
}

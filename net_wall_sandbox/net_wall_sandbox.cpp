
#include <iostream>
#include <net_wall.h>
int main()
{
    net_wall::net_wall* wall;
    net_wall::net_wall_rule* rule;
    std::cout << (net_wall::Init()==true?"Success":"Oops")<<std::endl;
    try {
        net_wall::Initialize(&wall, net_wall::FWProfile::__PUBLIC);
        net_wall::GetRule("Shell", wall, &rule);
        if (net_wall::GetProtocol(rule) == net_wall::Protocol::ANY || net_wall::GetProtocol(rule) == net_wall::Protocol::TCP) {
            net_wall::SetProtocol(rule, net_wall::Protocol::UDP);
        }
        else {
            net_wall::SetProtocol(rule, net_wall::Protocol::TCP);
        }
        if (net_wall::GetBound(rule) == net_wall::Bound::B_MAX || net_wall::GetBound(rule) == net_wall::Bound::B_INBOUND) {
            net_wall::SetBound(rule, net_wall::Bound::B_OUTBOUND);
        }
        else {
            net_wall::SetBound(rule, net_wall::Bound::B_INBOUND);
        }

        net_wall::Cleanup(wall);
    }
    catch (net_wall::permission_denied& pm) {
        std::cerr << pm.what << std::endl;
        net_wall::Cleanup(wall);
    }
    net_wall::Free();
    return 0;
}

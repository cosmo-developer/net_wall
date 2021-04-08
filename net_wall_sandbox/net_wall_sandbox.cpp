
#include <iostream>
#include "net_wall.h"

int main()
{
    net_wall::net_wall* nwall;
    net_wall::net_wall_rule* myrule=NULL;
    try {
        net_wall::Initialize(&nwall, net_wall::FWProfile::__PUBLIC);
        std::cout << net_wall::IsEnabled(nwall) << std::endl;
        //net_wall::SetEnabled(nwall, false);
        std::cout << net_wall::IsEnabled(nwall) << std::endl;
        std::cout << (net_wall::GetProfile(nwall) == net_wall::FWProfile::__PUBLIC) << std::endl;
        std::cout << (net_wall::GetDefaultInboundAction(nwall)==net_wall::FWAction::FWA_BLOCK) << std::endl;
        
        //net_wall::RemoveRule(nwall,"Cosmo Group");
        net_wall::RemoveRule(nwall, "Cosmo Group");
        std::cout << (myrule == NULL) << std::endl;
        net_wall::Cleanup(nwall);
    }
    catch (net_wall::permission_denied& pm) {
        std::cerr << pm.what << std::endl;
    }
    return 0;
}

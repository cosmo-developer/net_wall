#pragma once
#include "net_wall.h"

namespace net_wall {
	struct net_list_manager {};//implementation provided by platform

	extern "C++" {
		void NET_WALL_API NET_WALL_CALL InitializeNetListManager(net_list_manager**);
		void NET_WALL_API NET_WALL_CALL Cleanup(net_list_manager*);

	}
}
// See the file  in the main distribution directory for copyright.
#include "plugin/Plugin.h"

#include "XMPP.h"

namespace plugin {
namespace Zeek_XMPP {

class Plugin : public plugin::Plugin {
public:
	plugin::Configuration Configure()
		{
		AddComponent(new ::analyzer::Component("XMPP", ::analyzer::xmpp::XMPP_Analyzer::Instantiate));

		plugin::Configuration config;
		config.name = "Zeek::XMPP";
		config.description = "XMPP analyzer (StartTLS only)";
		return config;
		}
} plugin;

}
}

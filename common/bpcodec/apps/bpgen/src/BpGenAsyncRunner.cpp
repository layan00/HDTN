#include "BpGenAsyncRunner.h"
#include <iostream>
#include "SignalHandler.h"
#include <boost/filesystem.hpp>
#include <boost/program_options.hpp>
#include <boost/lexical_cast.hpp>


void BpGenAsyncRunner::MonitorExitKeypressThreadFunction() {
    std::cout << "Keyboard Interrupt.. exiting\n";
    m_runningFromSigHandler = false; //do this first
}



static void DurationEndedThreadFunction(const boost::system::error_code& e, volatile bool * running) {
    if (e != boost::asio::error::operation_aborted) {
        // Timer was not cancelled, take necessary action.
        std::cout << "BpGen reached duration.. exiting\n";
    }
    else {
        std::cout << "Unknown error occurred in DurationEndedThreadFunction " << e.message() << std::endl;
    }
    *running = false;
}

BpGenAsyncRunner::BpGenAsyncRunner() {}
BpGenAsyncRunner::~BpGenAsyncRunner() {}


bool BpGenAsyncRunner::Run(int argc, const char* const argv[], volatile bool & running, bool useSignalHandler) {
    //scope to ensure clean exit before return 0
    {
        running = true;
        m_runningFromSigHandler = true;
        SignalHandler sigHandler(boost::bind(&BpGenAsyncRunner::MonitorExitKeypressThreadFunction, this));
        uint32_t bundleSizeBytes;
        uint32_t bundleRate;
        //uint32_t tcpclFragmentSize;
        uint32_t durationSeconds;
        uint64_t flowId;
        OutductsConfig_ptr outductsConfig;

        boost::program_options::options_description desc("Allowed options");
        try {
                desc.add_options()
                    ("help", "Produce help message.")
                    ("bundle-size", boost::program_options::value<boost::uint32_t>()->default_value(100), "Bundle size bytes.")
                    ("bundle-rate", boost::program_options::value<boost::uint32_t>()->default_value(1500), "Bundle rate. (0=>as fast as possible)")
                    ("duration", boost::program_options::value<boost::uint32_t>()->default_value(0), "Seconds to send bundles for (0=>infinity).")
                    ("flow-id", boost::program_options::value<uint64_t>()->default_value(2), "Destination flow id.")
                    ("outducts-config-file", boost::program_options::value<std::string>()->default_value("outducts.json"), "Outducts Configuration File.")
                    ;

                boost::program_options::variables_map vm;
                boost::program_options::store(boost::program_options::parse_command_line(argc, argv, desc, boost::program_options::command_line_style::unix_style | boost::program_options::command_line_style::case_insensitive), vm);
                boost::program_options::notify(vm);

                if (vm.count("help")) {
                        std::cout << desc << "\n";
                        return false;
                }

                const std::string configFileName = vm["outducts-config-file"].as<std::string>();

                outductsConfig = OutductsConfig::CreateFromJsonFile(configFileName);
                if (!outductsConfig) {
                    std::cerr << "error loading config file: " << configFileName << std::endl;
                    return false;
                }
                std::size_t numBpGenOutducts = outductsConfig->m_outductElementConfigVector.size();
                if (numBpGenOutducts != 1) {
                    std::cerr << "error: number of bpgen outducts is not 1: got " << numBpGenOutducts << std::endl;
                }

                bundleSizeBytes = vm["bundle-size"].as<boost::uint32_t>();
                bundleRate = vm["bundle-rate"].as<boost::uint32_t>();
                durationSeconds = vm["duration"].as<boost::uint32_t>();
                flowId = vm["flow-id"].as<uint64_t>();
                
        }
        catch (boost::bad_any_cast & e) {
                std::cout << "invalid data error: " << e.what() << "\n\n";
                std::cout << desc << "\n";
                return false;
        }
        catch (std::exception& e) {
                std::cerr << "error: " << e.what() << "\n";
                return false;
        }
        catch (...) {
                std::cerr << "Exception of unknown type!\n";
                return false;
        }


        std::cout << "starting BpGenAsync.." << std::endl;

        BpGenAsync bpGen;
        bpGen.Start(*outductsConfig, bundleSizeBytes, bundleRate, flowId);

        boost::asio::io_service ioService;
        boost::asio::deadline_timer deadlineTimer(ioService, boost::posix_time::seconds(durationSeconds));
        if (durationSeconds) {
            deadlineTimer.async_wait(boost::bind(&DurationEndedThreadFunction, boost::asio::placeholders::error, &running));
        }

        if (useSignalHandler) {
            sigHandler.Start(false);
        }
        std::cout << "BpGenAsync up and running" << std::endl;
        while (running && m_runningFromSigHandler) {
            boost::this_thread::sleep(boost::posix_time::millisec(250));
            if (durationSeconds) {
                ioService.poll_one();
            }
            if (useSignalHandler) {
                sigHandler.PollOnce();
            }
        }

       //std::cout << "Msg Count, Bundle Count, Bundle data bytes\n";

        //std::cout << egress.m_messageCount << "," << egress.m_bundleCount << "," << egress.m_bundleData << "\n";


        std::cout<< "BpGenAsyncRunner::Run: exiting cleanly..\n";
        bpGen.Stop();
        m_bundleCount = bpGen.m_bundleCount;
        m_outductFinalStats = bpGen.m_outductFinalStats;
    }
    std::cout<< "BpGenAsyncRunner::Run: exited cleanly\n";
    return true;

}
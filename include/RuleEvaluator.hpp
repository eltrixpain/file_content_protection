#ifndef RULE_EVALUATOR_HPP
#define RULE_EVALUATOR_HPP

#include "ConfigManager.hpp"
#include <linux/fanotify.h>
#include <string>

class RuleEvaluator {
public:
    RuleEvaluator(const ConfigManager& config);
    
    // main handler: takes fanotify event and returns whether to allow or deny
void handle_event(int fan_fd,
                  const struct fanotify_event_metadata* metadata,
                  pid_t logger_pid,
                  int log_pipe_fd,
                  int& out_decision);
private:
    const ConfigManager& config;
};

#endif // RULE_EVALUATOR_HPP

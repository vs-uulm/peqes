library(tidyverse)
library(scales)

pdf(NULL)

data <- read_csv("results/computation/results.csv", col_names = c("type", "responses", "time"), col_types = "ccc") %>%
    mutate(
        responses = parse_number(responses),
        time = parse_number(substr(time, 0, nchar(time) - 6)) / 1000
    ) %>%
    group_by(responses, type) %>%
    summarize(
        t.min = min(time),
        t.max = max(time),
        t.mean = mean(time),
        t.sd = sd(time),
        t.num = n()
    ) %>% mutate(
        te.se = t.sd / sqrt(t.num),
        t.m.ci.h = t.mean - qt(1 - (0.05 / 2), t.num - 1) * te.se,
        t.m.ci.l = t.mean + qt(1 - (0.05 / 2), t.num - 1) * te.se
    )

data %>% filter(responses < 10000) %>% ggplot(aes(x=reorder(responses, desc(responses)), y=t.mean)) +
        geom_bar(aes(fill=reorder(type, desc(type))), alpha=.5, stat="identity", color="black", size=.1, width=.5, position = "dodge2") + 
        geom_errorbar(aes(fill=reorder(type, desc(type)), ymin=t.m.ci.l, ymax=t.m.ci.h), size=.2, width=.5, position = "dodge2") + 
        scale_fill_manual(values=c("#d08f97", "#8fa9bd"), name="Type", guide = guide_legend(reverse=F)) +
        xlab("#Responses") +
        ylab("Time [s]") +
        theme(legend.position = "top") +
        coord_flip()

write_csv(data, "results/computation-stats.csv")
ggsave("results/computation.pdf", plot = last_plot(), scale = 1, width = 84.75, height = 50, units = "mm", dpi = 300)


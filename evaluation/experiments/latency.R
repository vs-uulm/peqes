library(tidyverse)
library(scales)

pdf(NULL)

files = c("results/latency/sgx/times.csv", "results/latency/baseline/times.csv")

data <- files %>%
    map_df(function(x) read_csv(x, col_names = FALSE, col_types = "cccc")
         %>% mutate(X2=parse_number(substr(X2, 0, nchar(X2) - 3)))
         %>% mutate(X3=parse_number(substr(X3, 0, nchar(X3) - 3)))
         %>% mutate(X4=parse_number(substr(X4, 0, nchar(X4) - 3)))
         %>% mutate(type = unlist(strsplit(x, split="/"))[3])
         %>% mutate(time = (X2+X3+X4) / 1000))

results <- data %>% group_by(type) %>% summarize(
        t.min = min(time),
        t.max = max(time),
        t.mean = mean(time),
        t.median = median(time),
        t.sd = sd(time),
        t.q99 = quantile(time, .99),
        t.num = n()
    )

data %>% ggplot(aes(x=type, y=time)) +
        geom_boxplot(aes(color=type), size=.2, position=position_dodge(0.95)) +
        scale_color_manual(values=c("#a32638", "#26547c"), name="Type", guide = guide_legend(reverse=F)) +
        xlab("Type") +
        ylab("Time [ms]") +
        theme(legend.position = "none") +
        scale_y_continuous(label=comma)

write_csv(results, "results/latency-stats.csv")
ggsave("results/latency.pdf", plot = last_plot(), scale = 1, width = 84.75, height = 60, units = "mm", dpi = 300)


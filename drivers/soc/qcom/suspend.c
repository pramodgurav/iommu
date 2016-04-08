/*
 * (C) Copyright 2016 Linaro Ltd.
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public License
 * as published by the Free Software Foundation; version 2
 * of the License.
 */
#include <linux/module.h>
#include <linux/of.h>
#include <linux/cpuidle.h>
#include <linux/suspend.h>


static void qcom_pm_enter_freeze(struct cpuidle_device *dev,
	struct cpuidle_driver *drv,
	int index)
{
	drv->states[index].enter(dev, drv, index);
}

static const struct of_device_id qcom_idle_state_match[] = {
	{ .compatible = "qcom,idle-state-spc", },
	{ },
};

static const struct platform_suspend_ops qcom_suspend_ops = {
	.valid          = suspend_valid_only_mem,
};

static int __init qcom_pm_init(void)
{
	struct cpuidle_device *cpu_dev;
	struct cpuidle_driver *cpu_drv;
	int state_count;
	struct device_node *state_np, *cpu_np;
	const struct of_device_id *match;
	int i;

	/* configure CPU enter_freeze if applicable */
	for_each_present_cpu(i) {
		cpu_np = of_get_cpu_node(i, NULL);
		cpu_dev = per_cpu_ptr(cpuidle_devices, i);
		cpu_drv = cpuidle_get_cpu_driver(cpu_dev);

		if (!cpu_dev || !cpu_drv) {
			of_node_put(cpu_np);
			return -EPROBE_DEFER;
		}

		state_count = 0;
		state_np = of_parse_phandle(cpu_np, "cpu-idle-states",
						  state_count);

		while (state_np) {
			match = of_match_node(qcom_idle_state_match,
					      state_np);

			state_count++;
			if (match)
				cpu_drv->states[state_count].enter_freeze =
						&qcom_pm_enter_freeze;
			of_node_put(state_np);

			state_np = of_parse_phandle(cpu_np, "cpu-idle-states",
						    state_count);
		}

		of_node_put(cpu_np);
	}

	suspend_set_ops(&qcom_suspend_ops);

	return 0;
}

late_initcall(qcom_pm_init);

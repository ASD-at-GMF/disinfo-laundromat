<script lang="ts">
	import { Select } from 'bits-ui';
	import type { SelectTriggerProps } from 'bits-ui';
	import { cn } from '$utils';
	let restProps = $$restProps as SelectTriggerProps;
	let className: SelectTriggerProps["class"] = undefined;
	export {className as class}

	</script>

<Select.Trigger {...restProps} class={cn('', className)}>
	<slot />
</Select.Trigger>


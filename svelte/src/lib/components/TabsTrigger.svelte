<script lang="ts">
	import { Tabs, type TabsTriggerProps } from 'bits-ui';
	import { cn } from '$utils';

	const restProps = $$restProps as TabsTriggerProps;
	const className: TabsTriggerProps['class'] = undefined;
	export { className as class };
</script>

<Tabs.Trigger class={cn('', className)} {...restProps}>
	<slot />
</Tabs.Trigger>

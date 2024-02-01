<script lang="ts">
	import { Tabs } from 'bits-ui';
	import type { TabsListProps } from 'bits-ui';
	import { cn } from '$utils';
	const restProps = $$restProps as TabsListProps;
	let className: TabsListProps['class'] = undefined;
	export { className as class };
</script>

<Tabs.List {...restProps} class={cn('w-100 flex justify-between', className)}>
	<slot />
</Tabs.List>

<script lang="ts">
	import { Tabs } from 'bits-ui';
	import type { TabsContentProps } from 'bits-ui';
	import { cn } from '$utils';
	const restProps = $$restProps as TabsContentProps;
	let className: TabsContentProps['class'] = undefined;
	export { className as class };
</script>

<Tabs.Content {...restProps} class={cn('', className)}>
	<slot />
</Tabs.Content>

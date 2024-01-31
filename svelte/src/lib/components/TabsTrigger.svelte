<script lang="ts">
	import { Tabs } from 'bits-ui';
	import { cn } from '$utils';
	export let value: string;
	export let className: string | undefined = undefined;
</script>

<Tabs.Trigger
	{value}
	class={cn(
		'data-[state=active]:shadow-mini dark:data-[state=active]:bg-background flex-1 data-[state=active]:bg-white',
		className
	)}
>
	<slot />
</Tabs.Trigger>

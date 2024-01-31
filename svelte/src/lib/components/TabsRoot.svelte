<script lang="ts">
	import { Tabs } from 'bits-ui';
	import { cn } from '$utils';
	export let value: string | undefined;
	export let className: string | undefined = undefined;
</script>

<Tabs.Root {value} class={cn('w-100 h-100 border-muted shadow-card border bg-blue-500', className)}>
	<slot />
</Tabs.Root>

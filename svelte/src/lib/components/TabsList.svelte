<script lang="ts">
	import { Tabs } from 'bits-ui';
	import { cn } from '$utils';
	export let className: string | undefined = undefined;
</script>

<Tabs.List class={cn('w-100 flex justify-between', className)}>
	<slot />
</Tabs.List>

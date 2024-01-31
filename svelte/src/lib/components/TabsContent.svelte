<script lang="ts">
	import { Tabs } from 'bits-ui';
	import { cn } from '$utils';
	export let value: string;
	export let className: string | undefined = undefined;
</script>

<Tabs.Content {value} class={cn('', className)}>
	<slot />
</Tabs.Content>

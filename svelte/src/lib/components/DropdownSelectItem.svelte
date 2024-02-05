<!-- Wrapper component based on https://www.bits-ui.com/docs/components/select -->
<script lang="ts">
	import { Select } from 'bits-ui';
	let value: string;
	let label: string;
	export { value, label };
</script>

<Select.Item
	class="rounded-button data-[highlighted]:bg-muted flex h-10 w-full select-none items-center py-3 pl-5 pr-1.5 text-sm outline-none transition-all duration-75"
	{value}
	{label}
	{...$$restProps}
>
	{label}
	<Select.ItemIndicator class="ml-auto" asChild={false}>S</Select.ItemIndicator>
</Select.Item>

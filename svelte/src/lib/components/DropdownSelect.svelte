<!-- Wrapper component based on https://www.bits-ui.com/docs/components/select -->
<script lang="ts">
	import { Select, type Selected, type SelectProps } from 'bits-ui';
	import type { LabeledValue } from "$types";
	export let name: string;
	export let value: LabeledValue;
	let className: string | undefined = undefined;
	export { className as class };

//	function handleSelectedChange(value: Selected<unknown> | undefined) {
//		if (value  && onSelectedChange) {
//			if (Array.isArray(value)) {
//				let str = value
//					.filter((v: Selected<unknown>) => v.value)
//					.map((v: Selected<unknown>) => v.value)
//					.join(',');
//				onSelectedChange(str, name);
//			} else if (value.value) {
//				onSelectedChange(value.value as string, name);
//			} else {
//				console.warn('Dropdown value(s) are undefined');
//			}
//		}
//	}


</script>

<div id={name} class={className}>
	<Select.Root {name} bind:selected={value} {...$$restProps}>
		<Select.Trigger
			class="h-input border-border-input bg-background placeholder:text-foreground-alt/50 focus:ring-foreground focus:ring-offset-background inline-flex items-center border px-[11px]  text-sm transition-colors focus:outline-none focus:ring-2 focus:ring-offset-2"
			aria-label="Select a item"
		>
			<Select.Value class="text-sm" />
		</Select.Trigger>
		<Select.Content
			class="border-muted bg-background shadow-popover w-full border px-1 py-3 outline-none"
			sideOffset={8}
		>
			<slot />
		</Select.Content>
		<select.input />
	</Select.Root>
</div>

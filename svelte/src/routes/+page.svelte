<script lang="ts">
	import TabsRoot from '$components/TabsRoot.svelte';
	import TabsList from '$components/TabsList.svelte';
	import TabsTrigger from '$components/TabsTrigger.svelte';
	import TabsContent from '$components/TabsContent.svelte';
	
	import { Label, Select } from 'bits-ui';
	const themes = [
		{ value: 'light-monochrome', label: 'Light Monochrome' },
		{ value: 'dark-green', label: 'Dark Green' },
		{ value: 'svelte-orange', label: 'Svelte Orange' },
		{ value: 'punk-pink', label: 'Punk Pink' }
	];
</script>

<main class="w-100">
	<section class="grid grid-rows-2 gap-4">
		<div class=" grid grid-cols-1 gap-4 md:grid-cols-2">
			<div class="bg-blue-300">Explanation</div>
			<div class="">
				<TabsRoot value="content similarity">
					<TabsList>
						<TabsTrigger value="content similarity">Content similarity</TabsTrigger>
						<TabsTrigger value="metadata similarity">Metadata similarity</TabsTrigger>
					</TabsList>
					<TabsContent value="content similarity">
						<p>
							Search for similar content shared across the internet. Laundromat uses popular search
							engines to find related websites. Discover networks of malicious actors/websites
							collectively sharing disinformation.
						</p>
						<Select.Root items={themes}>
							<Select.Trigger
								class="h-input rounded-9px border-border-input bg-background placeholder:text-foreground-alt/50 focus:ring-foreground focus:ring-offset-background inline-flex w-[296px] items-center border px-[11px]  text-sm transition-colors focus:outline-none focus:ring-2 focus:ring-offset-2"
								aria-label="Select a theme"
							>
								<Select.Value class="text-sm" placeholder="Select a theme" />
							</Select.Trigger>
							<Select.Content
								class="border-muted bg-background shadow-popover w-full rounded-xl border px-1 py-3 outline-none"
								sideOffset={8}
							>
								{#each themes as theme}
									<Select.Item
										class="rounded-button data-[highlighted]:bg-muted flex h-10 w-full select-none items-center py-3 pl-5 pr-1.5 text-sm outline-none transition-all duration-75"
										value={theme.value}
										label={theme.label}
									>
										{theme.label}
										<Select.ItemIndicator class="ml-auto" asChild={false}></Select.ItemIndicator>
									</Select.Item>
								{/each}
							</Select.Content>
							<Select.Input name="favoriteFruit" />
						</Select.Root>
					</TabsContent>
					<TabsContent value="metadata similarity">test 2 test 2</TabsContent>
				</TabsRoot>
			</div>
		</div>
		<div>
			<Label.Root for="use case list" class="bg-green-300">Label!</Label.Root>
			<ul id="use case list" class="grid grid-cols-1 gap-x-4 md:grid-cols-3">
				<li class="bg-pink-500">test1</li>
				<li class="bg-pink-500">test2</li>
				<li class="bg-pink-500">test3</li>
			</ul>
		</div>
	</section>
</main>

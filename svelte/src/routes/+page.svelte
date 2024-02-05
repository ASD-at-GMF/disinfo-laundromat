<script lang="ts">
	import TabsRoot from '$components/TabsRoot.svelte';
	import TabsList from '$components/TabsList.svelte';
	import TabsTrigger from '$components/TabsTrigger.svelte';
	import TabsContent from '$components/TabsContent.svelte';
	import DropdownSelect from '$components/DropdownSelect.svelte';
	import DropdownSelectItem from '$components/DropdownSelectItem.svelte';
	import { Label, Select } from 'bits-ui';
	import type { LabeledValue } from '$types';

	const dropdown_dummy_region: LabeledValue[] = [
		{ label: 'US', value: 'US' },
		{ label: 'NL', value: 'NL' }
	];

	const dropdown_dummy_language: LabeledValue[] = [
		{ label: 'english', value: 'english' },
		{ label: 'dutch', value: 'dutch' }
	];

	const dropdown_dummy_browser: LabeledValue[] = [
		{ label: 'all browsers', value: 'all_browsers'},
		{ label: 'Google', value: 'Google' },
		{ label: 'Bing', value: 'Bing' }
	];

	interface InputData {
		region: string;
		language: string;
		[index: string]: string;
	}

	let inputData: InputData = {
		region: '',
		language: ''
	};

	function handleDropdownSelectedChange(value: string, name: string) {
		if (inputData.hasOwnProperty(name)) {
			inputData[name] = value;
		} else {
			console.error(`Unknown property: ${name}`);
		}
		console.log(inputData);
	}

	function handleFormSubmit() {}
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
						<form>
							<div class="flex">
								<div> 
									<Label.Root for="content_search">language</Label.Root>
									<textarea 
										id="content_search"
										name="content search" 
										rows="4"
										cols="50"
										class="w-full resize-none"/>
								</div>
								<button type="submit">Submit</button>
							</div>

							<Label.Root for="region_input">browsers</Label.Root>
							<DropdownSelect
								id="region_input"
								name="region"
								selected={dropdown_dummy_region[0]}
								onSelectedChange={handleDropdownSelectedChange}
							>
								{#each dropdown_dummy_region as item}
									<DropdownSelectItem value={item.value} label={item.label}></DropdownSelectItem>
								{/each}
							</DropdownSelect>


							<Label.Root for="language_input">language</Label.Root>
							<DropdownSelect
								id="language_input"
								name="language"
								multiple={true}
								selected={dropdown_dummy_language[0]}
								onSelectedChange={handleDropdownSelectedChange}
							>
								{#each dropdown_dummy_language as item}
									<DropdownSelectItem value={item.value} label={item.label}></DropdownSelectItem>
								{/each}
							</DropdownSelect>

							<Label.Root for="browser_input">browser</Label.Root>
							<DropdownSelect
								id="browser_input"
								name="browser"
								multiple={true}
								selected={dropdown_dummy_browser[0]}
								onSelectedChange={handleDropdownSelectedChange}
							>
								{#each dropdown_dummy_browser as item}
									<DropdownSelectItem value={item.value} label={item.label}></DropdownSelectItem>
								{/each}
							</DropdownSelect>


							<form></form>
						</form></TabsContent
					>
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
